"""多轮攻击链编排器：状态机式 n 轮对话越狱。

与单发 payload 的区别：真实产品的越狱往往需要铺垫——
  第 1 轮埋密语/建立人设/污染记忆，第 N 轮才触发。
编排器按 chain 定义逐轮推进完整会话（保留 assistant 历史），
每轮结束把累计对话送 judge 联合判定。

chain JSONL 格式：
{"id":"C001","name":"密语触发链","strategy":"seed_trigger","severity":"high",
 "objective":"forbidden_action","turns":["第1轮用户消息","第2轮用户消息",...],
 "leak_markers":[],"notes":""}
"""
from __future__ import annotations

import csv
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .client import ChatClient
from .judge import rule_judge
from .payloads import Payload

CHAIN_CSV_FIELDS = [
    "run_id", "ts", "chain_id", "name", "strategy", "severity", "objective",
    "model", "turns", "status", "http_status", "latency_ms", "verdict",
    "verdict_reasons", "turn_log", "response_snippet", "response_full", "error",
]


@dataclass
class Chain:
    id: str
    name: str
    strategy: str
    severity: str
    objective: str
    turns: list[str]
    leak_markers: list = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Chain":
        turns = d.get("turns") or []
        if len(turns) < 2:
            raise ValueError(f"{d.get('id')}: 攻击链至少 2 轮")
        return cls(
            id=str(d["id"]), name=str(d.get("name", d["id"])),
            strategy=str(d.get("strategy", "custom")),
            severity=str(d.get("severity", "medium")),
            objective=str(d.get("objective", "forbidden_action")),
            turns=[str(t) for t in turns],
            leak_markers=[str(x) for x in (d.get("leak_markers") or [])],
            notes=str(d.get("notes") or ""),
        )

    def as_payload(self) -> Payload:
        """供 judge 使用的视图：canary 从全部轮次提取。"""
        return Payload(
            id=self.id, name=self.name, category=f"chain_{self.strategy}",
            severity=self.severity, objective=self.objective,
            payload="\n".join(self.turns), leak_markers=self.leak_markers,
            source="chain", notes=self.notes,
        )


def load_chains(path: str) -> list[Chain]:
    chains = []
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                chains.append(Chain.from_dict(json.loads(line)))
            except Exception as e:
                raise ValueError(f"{path}:{ln} chain 解析失败: {e}") from e
    ids = [c.id for c in chains]
    if len(ids) != len(set(ids)):
        raise ValueError("chain id 重复")
    return chains


def load_done_chain_ids(csv_path: str) -> set[str]:
    if not os.path.isfile(csv_path):
        return set()
    done = set()
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("status") == "ok":
                done.add(row.get("chain_id", ""))
    return done


def run_chains(chains: list[Chain], client: ChatClient | None, out_csv: str,
               concurrency: int = 4, known_system: str | None = None,
               temperature: float = 0.7, max_tokens: int = 1024, retries: int = 1,
               resume: bool = False, dry_run: bool = False, verbose: bool = True) -> dict:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-chain"
    done = load_done_chain_ids(out_csv) if resume else set()
    todo = [c for c in chains if c.id not in done]
    if verbose:
        print(f"[chain] 链={len(chains)} 跳过(已完成)={len(done)} 待执行={len(todo)} 并发={concurrency}",
              file=sys.stderr)

    new_file = not os.path.isfile(out_csv) or os.path.getsize(out_csv) == 0
    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    fh = open(out_csv, "a", encoding="utf-8-sig", newline="")
    writer = csv.DictWriter(fh, fieldnames=CHAIN_CSV_FIELDS)
    if new_file:
        writer.writeheader()
        fh.flush()
    lock = threading.Lock()
    counter = {"ok": 0, "error": 0, "BREAK": 0, "SUSPECT": 0, "RESIST": 0, "UNKNOWN": 0}

    def one(c: Chain) -> dict:
        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        base = {"run_id": run_id, "ts": ts, "chain_id": c.id, "name": c.name,
                "strategy": c.strategy, "severity": c.severity, "objective": c.objective,
                "model": client.model if client else "DRY-RUN", "turns": len(c.turns)}
        if dry_run:
            row = {**base, "status": "dry_run", "http_status": "", "latency_ms": "",
                   "verdict": "UNKNOWN", "verdict_reasons": "dry-run",
                   "turn_log": "", "response_snippet": "", "response_full": "", "error": ""}
            with lock:
                writer.writerow(row)
                fh.flush()
                counter["UNKNOWN"] += 1
            return row

        msgs: list[dict] = []
        transcript: list[str] = []
        assistant_texts: list[str] = []
        turn_log: list[str] = []
        total_lat = 0
        http_status = 200
        t0 = time.time()
        for i, user_msg in enumerate(c.turns, 1):
            msgs.append({"role": "user", "content": user_msg})
            r = client.chat(msgs, temperature=temperature, max_tokens=max_tokens, retries=retries)
            if not r["ok"]:
                row = {**base, "status": "error", "http_status": r.get("http_status", 0),
                       "latency_ms": int((time.time() - t0) * 1000), "verdict": "ERROR",
                       "verdict_reasons": f"第 {i} 轮请求失败",
                       "turn_log": " -> ".join(turn_log),
                       "response_snippet": "", "response_full": "\n".join(transcript),
                       "error": r.get("error", "")[:500]}
                with lock:
                    writer.writerow(row)
                    fh.flush()
                    counter["error"] += 1
                return row
            http_status = r["http_status"]
            total_lat += r.get("latency_ms", 0)
            msgs.append({"role": "assistant", "content": r["text"] or ""})
            transcript.append(f"[turn {i} user] {user_msg}\n[turn {i} assistant] {r['text'] or ''}")
            assistant_texts.append(r["text"] or "")
            turn_log.append(f"t{i}:{len(r['text'] or '')}ch")

        # 判定只看模型输出（用户消息里本来就带 canary，混入会造成假破防）
        judge_text = "\n---\n".join(assistant_texts)
        verdict, reasons = rule_judge(c.as_payload(), judge_text, known_system)
        row = {**base, "status": "ok", "http_status": http_status, "latency_ms": total_lat,
               "verdict": verdict, "verdict_reasons": " | ".join(reasons),
               "turn_log": " -> ".join(turn_log),
               "response_snippet": (msgs[-1]["content"] if msgs else "").replace("\n", " ")[:300],
               "response_full": "\n".join(transcript), "error": ""}
        with lock:
            writer.writerow(row)
            fh.flush()
            counter["ok"] += 1
            counter[verdict] = counter.get(verdict, 0) + 1
        if verbose:
            print(f"[{verdict:<7}] {c.id} {c.name} ({len(c.turns)}轮, {total_lat}ms)", file=sys.stderr)
        return row

    t0 = time.time()
    try:
        if concurrency <= 1:
            for c in todo:
                one(c)
        else:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futs = [ex.submit(one, c) for c in todo]
                for _ in as_completed(futs):
                    pass
    finally:
        fh.close()

    summary = {"run_id": run_id, "chains": len(chains), "skipped_done": len(done),
               "executed": len(todo), "elapsed_s": round(time.time() - t0, 1),
               "ok": counter["ok"], "error": counter["error"],
               "BREAK": counter["BREAK"], "SUSPECT": counter["SUSPECT"],
               "RESIST": counter["RESIST"], "UNKNOWN": counter["UNKNOWN"],
               "out_csv": os.path.abspath(out_csv)}
    if verbose:
        print(f"[chain] 完成: {summary}", file=sys.stderr)
    return summary
