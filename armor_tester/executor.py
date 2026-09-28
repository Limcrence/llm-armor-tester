"""并发执行引擎：批量投递 payload -> 目标端点 -> 落 CSV（断点续作）。

差异化能力：
  * --repeat N   概率破防采样：同一 payload 发 N 次，报告输出破防率
  * --carrier X  间接注入载体：邮件/网页/工具返回/日志/JSON 字段包装投递
  * follow_up    多轮攻击链：首轮埋点 -> 二轮触发，两轮联合判定
"""
from __future__ import annotations

import csv
import os
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .client import ChatClient
from .judge import rule_judge
from .mutate import apply_carrier
from .payloads import Payload

CSV_FIELDS = [
    "run_id", "ts", "payload_id", "name", "category", "severity", "objective",
    "model", "carrier", "sample", "turns", "status", "http_status", "latency_ms",
    "verdict", "verdict_reasons", "response_snippet", "response_full", "error",
    "source", "parent_id",
]


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_done_counts(csv_path: str) -> dict[str, int]:
    """断点续作：统计每条 payload 已完成的采样次数（status=ok）。"""
    counts: dict[str, int] = {}
    if not os.path.isfile(csv_path):
        return counts
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("status") in ("ok", "dry_run"):
                pid = row.get("payload_id", "")
                counts[pid] = counts.get(pid, 0) + 1
    return counts


def build_messages(p: Payload, system_message: str | None, carrier: str = "none") -> list[dict]:
    msgs: list[dict] = []
    sys_text = p.system_prompt_override or system_message
    if sys_text:
        msgs.append({"role": "system", "content": sys_text})
    msgs.append({"role": "user", "content": apply_carrier(p.payload, carrier) if carrier != "none" else p.payload})
    return msgs


def execute_payload(p: Payload, client: ChatClient, system_message: str | None,
                    carrier: str, temperature: float, max_tokens: int,
                    retries: int) -> dict:
    """单条 payload 完整执行（含 follow_up 多轮链）。"""
    msgs = build_messages(p, system_message, carrier)
    t0 = time.time()
    r1 = client.chat(msgs, temperature=temperature, max_tokens=max_tokens, retries=retries)
    if not r1["ok"]:
        return {"ok": False, "http_status": r1.get("http_status", 0), "text": "",
                "latency_ms": r1.get("latency_ms", 0), "turns": 1, "error": r1.get("error", "")}
    text = r1["text"] or ""
    turns = 1
    if p.follow_up:
        msgs2 = msgs + [
            {"role": "assistant", "content": r1["text"] or ""},
            {"role": "user", "content": apply_carrier(p.follow_up, carrier) if carrier != "none" else p.follow_up},
        ]
        r2 = client.chat(msgs2, temperature=temperature, max_tokens=max_tokens, retries=retries)
        turns = 2
        if r2["ok"]:
            text = (text + "\n---[turn2]---\n" + (r2["text"] or ""))
        else:
            text = (text + "\n---[turn2 error]---\n" + (r2.get("error", "")[:300]))
    return {"ok": True, "http_status": r1["http_status"], "text": text,
            "latency_ms": int((time.time() - t0) * 1000), "turns": turns, "error": ""}


class RateLimiter:
    """全局 QPS 闸门：多线程共享，超发请求排队而非并发打满目标端点。"""

    def __init__(self, qps: float = 0.0):
        self.interval = 1.0 / qps if qps and qps > 0 else 0.0
        self.lock = threading.Lock()
        self.next_t = 0.0

    def acquire(self):
        if not self.interval:
            return
        with self.lock:
            now = time.time()
            wait = max(0.0, self.next_t - now)
            self.next_t = max(now, self.next_t) + self.interval
        if wait:
            time.sleep(wait)


def run_campaign(payloads: list[Payload], client: ChatClient | None, out_csv: str,
                 concurrency: int = 8, system_message: str | None = None,
                 known_system: str | None = None, temperature: float = 0.7,
                 max_tokens: int = 1024, retries: int = 2, repeat: int = 1,
                 carrier: str = "none", resume: bool = False, dry_run: bool = False,
                 qps: float = 0.0, verbose: bool = True) -> dict:
    """执行一轮批量测试。返回统计摘要。"""
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    done_counts = load_done_counts(out_csv) if resume else {}
    jobs: list[tuple[Payload, int]] = []
    skipped = 0
    for p in payloads:
        have = done_counts.get(p.id, 0)
        for s in range(repeat):
            if s < have:
                skipped += 1
            else:
                jobs.append((p, s + 1))
    if verbose:
        print(f"[run] run_id={run_id} payload={len(payloads)} 采样x{repeat} "
              f"跳过(已完成)={skipped} 待执行={len(jobs)} 并发={concurrency} "
              f"载体={carrier} dry_run={dry_run}", file=sys.stderr)

    new_file = not os.path.isfile(out_csv) or os.path.getsize(out_csv) == 0
    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    fh = open(out_csv, "a", encoding="utf-8-sig", newline="")
    writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
    if new_file:
        writer.writeheader()
        fh.flush()
    lock = threading.Lock()
    counter = {"ok": 0, "error": 0, "BREAK": 0, "SUSPECT": 0, "RESIST": 0, "UNKNOWN": 0}
    limiter = RateLimiter(qps)

    def write_row(row: dict):
        with lock:
            writer.writerow(row)
            fh.flush()

    def one(p: Payload, sample: int) -> dict:
        base = {
            "run_id": run_id, "ts": _now(), "payload_id": p.id, "name": p.name,
            "category": p.category, "severity": p.severity, "objective": p.objective,
            "model": client.model if client else "DRY-RUN", "carrier": carrier,
            "sample": sample, "turns": 1, "source": p.source,
            "parent_id": p.parent_id or "",
        }
        if dry_run:
            row = {**base, "status": "dry_run", "http_status": "", "latency_ms": "",
                   "verdict": "UNKNOWN", "verdict_reasons": "dry-run 未请求",
                   "response_snippet": "", "response_full": "", "error": ""}
            write_row(row)
            with lock:
                counter["UNKNOWN"] += 1
            return row

        if not dry_run:
            limiter.acquire()
        r = execute_payload(p, client, system_message, carrier,
                            temperature, max_tokens, retries)
        if not r["ok"]:
            row = {**base, "status": "error", "http_status": r.get("http_status", 0),
                   "latency_ms": r.get("latency_ms", ""), "verdict": "ERROR",
                   "verdict_reasons": "请求失败", "response_snippet": "",
                   "response_full": "", "error": r.get("error", "")[:1000]}
            write_row(row)
            with lock:
                counter["error"] += 1
            if verbose:
                print(f"[err ] {p.id}#{sample} {r.get('error', '')[:100]}", file=sys.stderr)
            return row

        verdict, reasons = rule_judge(p, r["text"], known_system)
        row = {**base, "turns": r["turns"], "status": "ok", "http_status": r["http_status"],
               "latency_ms": r["latency_ms"], "verdict": verdict,
               "verdict_reasons": " | ".join(reasons),
               "response_snippet": (r["text"] or "").replace("\n", " ")[:300],
               "response_full": r["text"] or "", "error": ""}
        write_row(row)
        with lock:
            counter["ok"] += 1
            counter[verdict] = counter.get(verdict, 0) + 1
        if verbose:
            print(f"[{verdict:<7}] {p.id}#{sample} {p.name} ({r['latency_ms']}ms, "
                  f"{r['turns']}轮)", file=sys.stderr)
        return row

    t0 = time.time()
    try:
        if concurrency <= 1:
            for p, s in jobs:
                one(p, s)
        else:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futs = [ex.submit(one, p, s) for p, s in jobs]
                for _ in as_completed(futs):
                    pass
    finally:
        fh.close()

    summary = {
        "run_id": run_id, "payloads": len(payloads), "repeat": repeat,
        "skipped_done": skipped, "executed": len(jobs),
        "elapsed_s": round(time.time() - t0, 1),
        "ok": counter["ok"], "error": counter["error"],
        "BREAK": counter["BREAK"], "SUSPECT": counter["SUSPECT"],
        "RESIST": counter["RESIST"], "UNKNOWN": counter["UNKNOWN"],
        "carrier": carrier, "out_csv": os.path.abspath(out_csv),
    }
    if verbose:
        print(f"[run] 完成: {summary}", file=sys.stderr)
    return summary
