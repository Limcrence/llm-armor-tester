"""全托管扫描器：一条命令跑完整个破甲流程并自动出报告。

  单发采样 -> 邮件载体 -> 多轮链 -> judge 复判 -> 渗透报告 -> 深度分析
强度预设：
  quick    20 条核心载荷（约 2 分钟，快速摸底）
  standard 93 条全量 + 2 采样 + 6 链（默认，全面评估）
  full     693 条（含变异库）+ 3 采样（出具正式评估报告用）
"""
from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime

from .analyze import build_analysis
from .chains import load_chains, run_chains
from .client import ChatClient
from .executor import run_campaign
from .judge import rule_judge, llm_judge
from .payloads import load_payloads, filter_payloads
from . import report as report_mod

QUICK_IDS = ("P101,P103,P104,P105,P106,P107,P112,P113,P115,P117,"
             "P118,P002,P005,P006,P014,P024,P049,P050,R001,R030")

PRESETS = {
    "quick":    {"ids": QUICK_IDS, "repeat": 1, "carrier": False, "chains": True},
    "standard": {"ids": None, "repeat": 2, "carrier": True, "chains": True},
    "full":     {"ids": None, "repeat": 3, "carrier": True, "chains": True,
                 "payloads": ["payloads/*.jsonl"]},
}

PROFILE_FILE = "profiles.json"


def _log(step: str, msg: str):
    print(f"[{step}] {msg}", file=sys.stderr, flush=True)


def rejudge_csv(csv_path: str, out_path: str, client: ChatClient | None,
                known_system: str | None, mode: str = "rule") -> int:
    """对结果 CSV 重跑判定（规则 + 可选模型复核）。返回变更数。"""
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    lib = {p.id: p for p in load_payloads(_default_payload_paths())} if "payload_id" in fields else {}
    changed = 0
    for r in rows:
        if r.get("status") != "ok":
            continue
        p = lib.get(r.get("payload_id", ""))
        text = r.get("response_full") or ""
        if p is None or not text:
            continue
        verdict, reasons = rule_judge(p, text, known_system)
        if mode == "both" and client and verdict in ("SUSPECT", "UNKNOWN"):
            v2, r2 = llm_judge(client, p, text)
            reasons = reasons + r2
            if v2 in ("BREAK", "RESIST"):
                verdict = v2
        if verdict != r.get("verdict"):
            changed += 1
        r["verdict"] = verdict
        r["verdict_reasons"] = " | ".join(reasons)
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return changed


def _default_payload_paths() -> list[str]:
    return ["payloads/*.jsonl"]


def load_profile(name: str) -> dict:
    if not os.path.isfile(PROFILE_FILE):
        raise FileNotFoundError(f"配置档案不存在: {PROFILE_FILE}（先用 wizard 建一个）")
    with open(PROFILE_FILE, "r", encoding="utf-8") as f:
        profiles = json.load(f)
    if name not in profiles:
        raise KeyError(f"档案 {name} 不存在，可用: {', '.join(profiles) or '(空)'}")
    return profiles[name]


def save_profile(name: str, cfg: dict):
    profiles = {}
    if os.path.isfile(PROFILE_FILE):
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            profiles = json.load(f)
    profiles[name] = {k: v for k, v in cfg.items()
                      if k in ("base_url", "api_key", "model", "analyst_model",
                               "system_file", "intensity", "repeat", "qps")}
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def run_scan(cfg: dict) -> dict:
    """cfg 必填：base_url / api_key / model；其余有默认。"""
    preset = PRESETS.get(cfg.get("intensity", "standard"), PRESETS["standard"])
    tag = cfg.get("tag") or datetime.now().strftime("%Y%m%d-%H%M")
    out_dir = cfg.get("out_dir", "results")
    rep_dir = cfg.get("rep_dir", "reports")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(rep_dir, exist_ok=True)

    # 载荷选择
    paths = cfg.get("payload_paths") or (preset.get("payloads") or _default_payload_paths())
    ps = load_payloads(paths)
    if preset.get("ids"):
        want = {x.strip() for x in preset["ids"].split(",")}
        ps = [p for p in ps if p.id in want]
    if cfg.get("ids"):
        want = {x.strip() for x in cfg["ids"].split(",")}
        ps = [p for p in ps if p.id in want]
    repeat = int(cfg.get("repeat") or preset["repeat"])

    known_system = None
    if cfg.get("system_file") and os.path.isfile(cfg["system_file"]):
        with open(cfg["system_file"], "r", encoding="utf-8") as f:
            known_system = f.read()

    client = ChatClient(base_url=cfg["base_url"], api_key=cfg.get("api_key", ""),
                        model=cfg["model"], timeout=float(cfg.get("timeout", 120)),
                        no_proxy=bool(cfg.get("no_proxy", True)),
                        verify_ssl=not cfg.get("insecure", False))
    analyst = cfg.get("analyst_model") or ""
    judge_client = ChatClient(base_url=cfg["base_url"], api_key=cfg.get("api_key", ""),
                              model=analyst or cfg["model"],
                              timeout=float(cfg.get("timeout", 120)),
                              no_proxy=bool(cfg.get("no_proxy", True))) if cfg.get("judge_mode") == "both" else None

    result: dict = {"tag": tag, "intensity": cfg.get("intensity", "standard"),
                    "target": cfg["base_url"], "model": cfg["model"]}

    # 1) 单发采样
    _log("1/6", f"单发载荷 {len(ps)} 条 × 采样 {repeat}（qps={cfg.get('qps', 2)}）")
    run_csv = os.path.join(out_dir, f"{tag}.run.csv")
    run_campaign(ps, client, run_csv, concurrency=int(cfg.get("concurrency", 4)),
                 system_message=known_system, known_system=known_system,
                 temperature=float(cfg.get("temperature", 0.7)),
                 max_tokens=int(cfg.get("max_tokens", 1024)), retries=2,
                 repeat=repeat, carrier="none",
                 qps=float(cfg.get("qps", 2)), resume=bool(cfg.get("resume", True)),
                 verbose=False)
    result["run_csv"] = os.path.abspath(run_csv)

    # 2) 邮件载体
    if preset.get("carrier") and not cfg.get("no_carrier"):
        _log("2/6", "间接注入载体（email）")
        car_csv = os.path.join(out_dir, f"{tag}.carrier.csv")
        run_campaign(ps[:50], client, car_csv,
                     concurrency=int(cfg.get("concurrency", 4)),
                     system_message=known_system, known_system=known_system,
                     max_tokens=int(cfg.get("max_tokens", 1024)), retries=2,
                     repeat=1, carrier="email",
                     qps=float(cfg.get("qps", 2)), resume=bool(cfg.get("resume", True)),
                     verbose=False)
        result["carrier_csv"] = os.path.abspath(car_csv)
    else:
        _log("2/6", "跳过载体段")

    # 3) 多轮链
    if preset.get("chains") and not cfg.get("no_chains") and os.path.isfile(cfg.get("chains_path", "chains/attack_chains.jsonl")):
        _log("3/6", "多轮攻击链")
        ch_csv = os.path.join(out_dir, f"{tag}.chains.csv")
        run_chains(load_chains(cfg.get("chains_path", "chains/attack_chains.jsonl")),
                   client, ch_csv, concurrency=2,
                   known_system=known_system,
                   max_tokens=int(cfg.get("max_tokens", 1024)),
                   resume=bool(cfg.get("resume", True)), verbose=False)
        result["chains_csv"] = os.path.abspath(ch_csv)
    else:
        _log("3/6", "跳过攻击链段")

    # 4) judge 复判
    _log("4/6", f"judge 复判（mode={cfg.get('judge_mode', 'rule')}）")
    judged_csv = os.path.join(out_dir, f"{tag}.judged.csv")
    changed = rejudge_csv(run_csv, judged_csv, judge_client, known_system,
                          mode=cfg.get("judge_mode", "rule"))
    result["judged_csv"] = os.path.abspath(judged_csv)
    result["judge_changed"] = changed

    # 5) 渗透报告
    _log("5/6", "渗透报告")
    rep = report_mod.render(judged_csv, os.path.join(rep_dir, f"{tag}.report.md"),
                            target=cfg["base_url"], model=cfg["model"],
                            want_pdf=bool(cfg.get("pdf", True)),
                            payload_texts={p.id: p.payload for p in ps})
    result["report"] = rep

    # 6) 深度分析
    _log("6/6", "破防过程深度分析" + (f"（分析师: {analyst}）" if analyst else "（规则版）"))
    ana_client = None
    if analyst:
        ana_client = ChatClient(base_url=cfg["base_url"], api_key=cfg.get("api_key", ""),
                                model=analyst, timeout=float(cfg.get("timeout", 180)),
                                no_proxy=bool(cfg.get("no_proxy", True)))
    files = [judged_csv]
    for k in ("carrier_csv", "chains_csv"):
        if k in result:
            files.append(result[k])
    from .analyze import read_rows as _rr
    rows = _rr(files)
    md = build_analysis(rows, target=cfg["base_url"], model=cfg["model"],
                        client=ana_client, analyst_model=analyst,
                        top_n=int(cfg.get("top", 8)),
                        payload_texts={p.id: p.payload for p in ps})
    ana_md = os.path.join(rep_dir, f"{tag}.analysis.md")
    with open(ana_md, "w", encoding="utf-8") as f:
        f.write(md)
    ana_html = os.path.splitext(ana_md)[0] + ".html"
    with open(ana_html, "w", encoding="utf-8") as f:
        f.write(report_mod.md_to_html(md))
    ana_res = {"md": os.path.abspath(ana_md), "html": os.path.abspath(ana_html)}
    if cfg.get("pdf", True):
        ana_pdf = os.path.splitext(ana_md)[0] + ".pdf"
        if report_mod._headless_pdf(ana_html, ana_pdf):
            ana_res["pdf"] = os.path.abspath(ana_pdf)
    result["analysis"] = ana_res

    _log("完成", "全部产物：")
    for k, v in result.items():
        if isinstance(v, str) and (k.endswith("csv") or k.endswith("md")):
            print(f"    {k}: {v}", file=sys.stderr)
    for k in ("report", "analysis"):
        for kk, vv in (result.get(k) or {}).items():
            if isinstance(vv, str) and vv.endswith((".md", ".pdf")):
                print(f"    {k}.{kk}: {vv}", file=sys.stderr)
    return result
