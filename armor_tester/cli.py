"""LLM 破甲测试器 CLI。

子命令：
  payloads   payload 库查看/统计
  import-goods  引入外部破甲词（D:\\Goods 等）
  run        批量执行（落 CSV，支持断点续作/干跑）
  judge      对结果二次判定（规则 / 模型 judge）
  report     生成 Markdown/HTML/PDF 渗透报告
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import glob
import json
import os
import random
import sys

from .client import ChatClient
from .chains import load_chains, run_chains
from .analyze import build_analysis, read_rows as read_result_rows
from .compare import diff_results, render_diff_md
from .scan import run_scan, load_profile, save_profile, PRESETS, PROFILE_FILE
from .executor import run_campaign, build_messages
from .evolve import evolve
from .importers import import_goods
from .judge import rule_judge, llm_judge
from .mutate import expand, CARRIERS
from .payloads import load_payloads, filter_payloads, stats
from . import report as report_mod

DEFAULT_PAYLOAD_GLOBS = ["payloads/*.jsonl"]


def _load(args, required=True):
    paths = args.payloads or DEFAULT_PAYLOAD_GLOBS
    try:
        ps = load_payloads(paths)
    except Exception as e:
        if required:
            print(f"[!] payload 库加载失败: {e}", file=sys.stderr)
            sys.exit(2)
        return []
    return filter_payloads(ps, category=args.category, objective=args.objective,
                           severity=args.severity, tag=args.tag, ids=getattr(args, "ids", None))


def cmd_payloads(args):
    ps = _load(args)
    if args.action == "stats":
        print(json.dumps(stats(ps), ensure_ascii=False, indent=2))
        return
    for p in ps:
        if args.action == "list":
            print(f"{p.id:<6} [{p.severity:<6}] {p.category:<18} {p.objective:<16} {p.name}")
        else:  # show
            print(f"== {p.id} {p.name} ==")
            print(f"category={p.category} severity={p.severity} objective={p.objective} source={p.source}")
            print(f"canary={p.canaries()} leak_markers={p.leak_markers}")
            print(p.payload)
            print()


def cmd_import_goods(args):
    records = import_goods(args.goods_root)
    if args.dedupe and os.path.isfile(args.out):
        with open(args.out, "r", encoding="utf-8") as f:
            have = {json.loads(x).get("id") for x in f if x.strip()}
        records = [r for r in records if r["id"] not in have]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w" if not args.dedupe else "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[+] 引入 {len(records)} 条 -> {os.path.abspath(args.out)}")


def cmd_run(args):
    ps = _load(args)
    if args.limit:
        ps = ps[: args.limit]
    if not ps:
        print("[!] 无待执行 payload", file=sys.stderr)
        sys.exit(1)

    system_message = None
    known_system = None
    if args.system_file:
        with open(args.system_file, "r", encoding="utf-8") as f:
            known_system = f.read()
        system_message = args.system_message or known_system
    elif args.system_message:
        system_message = args.system_message

    client = None
    if not args.dry_run:
        if not args.base_url:
            print("[!] 缺少 --base-url（或设 ARMOR_BASE_URL）", file=sys.stderr)
            sys.exit(2)
        client = ChatClient(
            base_url=args.base_url, api_key=args.api_key or os.environ.get("ARMOR_API_KEY", ""),
            model=args.model, timeout=args.timeout, verify_ssl=not args.insecure,
            no_proxy=getattr(args, "no_proxy", False),
        )
    summary = run_campaign(
        ps, client, args.out, concurrency=args.concurrency,
        system_message=system_message, known_system=known_system,
        temperature=args.temperature, max_tokens=args.max_tokens,
        retries=args.retries, repeat=args.repeat, carrier=args.carrier,
        resume=args.resume, dry_run=args.dry_run, qps=args.qps,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if getattr(args, "analyze", False) and not args.dry_run:
        res = make_analysis(args, [args.out], os.path.splitext(args.out)[0] + ".analysis.md",
                            args.base_url or "", args.model)
        print(json.dumps({"analysis": res}, ensure_ascii=False, indent=2))


def cmd_chains(args):
    chains = load_chains(args.chains)
    known_system = None
    if args.system_file:
        with open(args.system_file, "r", encoding="utf-8") as f:
            known_system = f.read()
    client = None
    if not args.dry_run:
        if not args.base_url:
            print("[!] 缺少 --base-url（或设 ARMOR_BASE_URL）", file=sys.stderr)
            sys.exit(2)
        client = ChatClient(base_url=args.base_url, api_key=args.api_key or os.environ.get("ARMOR_API_KEY", ""),
                            model=args.model, timeout=args.timeout, verify_ssl=not args.insecure, no_proxy=getattr(args, "no_proxy", False))
    summary = run_chains(chains, client, args.out, concurrency=args.concurrency,
                         known_system=known_system, temperature=args.temperature,
                         max_tokens=args.max_tokens, retries=args.retries,
                         resume=args.resume, dry_run=args.dry_run)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def cmd_expand(args):
    ps = _load(args)
    muts = expand(ps, target=args.target, seed=args.seed, carrier=args.carrier, prefix=args.prefix)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for p in muts:
            d = dataclasses.asdict(p)
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(f"[+] 变异生成 {len(muts)} 条 -> {os.path.abspath(args.out)}")


def cmd_evolve(args):
    ps = _load(args)
    if not ps:
        print("[!] 无初始种群", file=sys.stderr)
        sys.exit(1)
    rng = random.Random(args.seed)
    pool = sorted(ps, key=lambda p: ({"high": 0, "medium": 1, "low": 2}[p.severity], p.id))
    initial = pool[: args.pop] if len(pool) >= args.pop else rng.sample(pool, len(pool))
    client = ChatClient(base_url=args.base_url, api_key=args.api_key or os.environ.get("ARMOR_API_KEY", ""),
                        model=args.model, timeout=args.timeout, verify_ssl=not args.insecure, no_proxy=getattr(args, "no_proxy", False))
    known_system = None
    if args.system_file:
        with open(args.system_file, "r", encoding="utf-8") as f:
            known_system = f.read()
    summary = evolve(initial, client, args.out_dir, gens=args.gens, pop_size=args.pop,
                     elite=args.elite, seed=args.seed, carrier=args.carrier,
                     known_system=known_system, temperature=args.temperature,
                     max_tokens=args.max_tokens, retries=args.retries,
                     concurrency=args.concurrency, repeat=args.repeat)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def cmd_diff(args):
    d = diff_results(args.old, args.new)
    md = render_diff_md(d)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md)
    print(json.dumps({k: len(v) if isinstance(v, list) else v for k, v in d.items()},
                     ensure_ascii=False, indent=2))


def make_analysis(args, results_files: list[str], out_md: str, target: str, model: str) -> dict:
    """生成破防过程深度分析报告（供 analyze 子命令与 run --analyze 复用）。"""
    payload_texts = {p.id: p.payload for p in _load(args, required=False)}
    client = None
    analyst_model = getattr(args, "analyst_model", "")
    if analyst_model:
        client = ChatClient(base_url=args.base_url, api_key=args.api_key or os.environ.get("ARMOR_API_KEY", ""),
                            model=analyst_model, timeout=args.timeout,
                            no_proxy=getattr(args, "no_proxy", False))
    rows = read_result_rows(results_files)
    md = build_analysis(rows, target=target, model=model, client=client,
                        analyst_model=analyst_model,
                        top_n=getattr(args, "top", 8),
                        payload_texts=payload_texts)
    os.makedirs(os.path.dirname(os.path.abspath(out_md)), exist_ok=True)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md)
    res = {"md": os.path.abspath(out_md), "rows": len(rows)}
    out_html = os.path.splitext(out_md)[0] + ".html"
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(report_mod.md_to_html(md))
    res["html"] = os.path.abspath(out_html)
    if getattr(args, "pdf", False):
        out_pdf = os.path.splitext(out_md)[0] + ".pdf"
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=report_mod.md_to_html(md)).write_pdf(out_pdf)
            res["pdf"] = os.path.abspath(out_pdf)
            res["pdf_engine"] = "weasyprint"
        except Exception:
            if report_mod._headless_pdf(out_html, out_pdf):
                res["pdf"] = os.path.abspath(out_pdf)
                res["pdf_engine"] = "headless-browser"
            else:
                res["pdf_error"] = "PDF 生成失败：可打印 HTML 为 PDF"
    return res


def cmd_analyze(args):
    res = make_analysis(args, args.results, args.out, args.target, args.model)
    print(json.dumps(res, ensure_ascii=False, indent=2))


def _scan_cfg(args) -> dict:
    prof = {}
    if getattr(args, "profile", None):
        prof = load_profile(args.profile)
    def pick(cli_val, key, default=None):
        return cli_val if cli_val not in (None, "") else prof.get(key, default)
    return {
        "base_url": pick(args.base_url, "base_url") or os.environ.get("ARMOR_BASE_URL", ""),
        "api_key": pick(args.api_key, "api_key") or os.environ.get("ARMOR_API_KEY", ""),
        "model": pick(args.model, "model", "gpt-4o-mini"),
        "analyst_model": pick(args.analyst_model, "analyst_model", ""),
        "system_file": pick(args.system_file, "system_file", ""),
        "intensity": pick(args.intensity, "intensity", "standard"),
        "repeat": pick(args.repeat, "repeat"),
        "qps": pick(args.qps, "qps", 2),
        "concurrency": args.concurrency, "timeout": args.timeout,
        "max_tokens": args.max_tokens, "temperature": args.temperature,
        "tag": args.tag, "out_dir": args.out_dir, "rep_dir": args.rep_dir,
        "ids": args.ids, "no_carrier": args.no_carrier, "no_chains": args.no_chains,
        "judge_mode": args.judge_mode, "top": args.top,
        "pdf": not args.no_pdf, "resume": not args.fresh,
        "insecure": args.insecure, "no_proxy": args.no_proxy,
    }


def cmd_scan(args):
    cfg = _scan_cfg(args)
    if not cfg["base_url"]:
        print("[!] 缺少目标端点：--base-url 或 --profile 或 ARMOR_BASE_URL", file=sys.stderr)
        sys.exit(2)
    res = run_scan(cfg)
    print(json.dumps({k: v for k, v in res.items() if not isinstance(v, dict)},
                     ensure_ascii=False, indent=2))


def cmd_wizard(args):
    def ask(label, default=""):
        hint = f" [{default}]" if default else ""
        val = input(f"{label}{hint}: ").strip()
        return val or default
    print("=== LLM 破甲测试器 · 交互向导 ===")
    cfg = {
        "base_url": ask("目标 API 地址（OpenAI 兼容，如 http://TARGET:PORT/v1）", "http://127.0.0.1:8080/v1"),
        "api_key": ask("API Key（无鉴权回车跳过）", ""),
        "model": ask("被测模型名", "gpt-4o-mini"),
        "analyst_model": ask("分析用模型（回车=纯规则分析）", ""),
        "system_file": ask("已知 system prompt 文件路径（回车=跳过泄露比对）", ""),
        "intensity": {"1": "quick", "2": "standard", "3": "full"}.get(
            ask("测试强度 1=快速摸底(2分钟) 2=标准(推荐) 3=全面", "2"), "standard"),
        "judge_mode": {"1": "rule", "2": "both"}.get(
            ask("判定方式 1=规则(快) 2=规则+模型复核(准)", "1"), "rule"),
        "qps": float(ask("限速 QPS（保护目标端点）", "2")),
        "no_proxy": ask("忽略系统代理直连？(y/n)", "y").lower() != "n",
        "pdf": ask("生成 PDF 报告？(y/n)", "y").lower() != "n",
        "resume": True, "concurrency": 4, "timeout": 180,
        "max_tokens": 1024, "temperature": 0.7,
    }
    name = ask("保存为配置档案名（下次 scan --profile 直接用，回车=不保存）", "")
    if name:
        save_profile(name, cfg)
        print(f"[+] 档案已保存: {name} -> {PROFILE_FILE}")
    print(f"\n[开始] 目标={cfg['base_url']} 模型={cfg['model']} 强度={cfg['intensity']}\n")
    res = run_scan(cfg)
    print(json.dumps({k: v for k, v in res.items() if not isinstance(v, dict)},
                     ensure_ascii=False, indent=2))


def cmd_profiles(args):
    if args.action == "list":
        if not os.path.isfile(PROFILE_FILE):
            print("（暂无档案，运行 wizard 或 scan --profile 名称 创建）")
            return
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        for n, c in profiles.items():
            print(f"{n:<16} {c.get('base_url', ''):<42} {c.get('model', ''):<22} 强度={c.get('intensity', 'standard')}")
    elif args.action == "show":
        print(json.dumps(load_profile(args.name), ensure_ascii=False, indent=2))
    elif args.action == "delete":
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        profiles.pop(args.name, None)
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles, f, ensure_ascii=False, indent=2)
        print(f"[+] 已删除 {args.name}")


def cmd_judge(args):
    rows = []
    with open(args.results, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        rows = list(reader)
    if "payload_text" not in fields:
        fields = list(fields) + ["payload_text"]

    payloads = {p.id: p for p in _load(args, required=False)}
    known_system = None
    if getattr(args, "system_file", None):
        with open(args.system_file, "r", encoding="utf-8") as f:
            known_system = f.read()

    client = None
    if args.mode in ("model", "both"):
        client = ChatClient(base_url=args.base_url, api_key=args.api_key or os.environ.get("ARMOR_API_KEY", ""),
                            model=args.judge_model, timeout=args.timeout,
                            no_proxy=getattr(args, "no_proxy", False))

    changed = 0
    for r in rows:
        text = r.get("response_full") or ""
        if not text or r.get("status") != "ok":
            continue
        p = payloads.get(r.get("payload_id"))
        if p is None:
            continue
        if args.mode == "rule":
            verdict, reasons = rule_judge(p, text, known_system)
        elif args.mode == "model":
            verdict, reasons = llm_judge(client, p, text)
        else:  # both：规则先行，SUSPECT/UNKNOWN 交模型复核
            verdict, reasons = rule_judge(p, text, known_system)
            if verdict in ("SUSPECT", "UNKNOWN"):
                v2, r2 = llm_judge(client, p, text)
                reasons = reasons + r2
                if v2 in ("BREAK", "RESIST"):
                    verdict = v2
        if verdict != r.get("verdict"):
            changed += 1
        r["verdict"] = verdict
        r["verdict_reasons"] = " | ".join(reasons)
        r["payload_text"] = p.payload

    with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] 复判完成，变更 {changed} 条 -> {os.path.abspath(args.out)}")


def cmd_report(args):
    payload_texts = {}
    ps = _load(args, required=False)
    payload_texts = {p.id: p.payload for p in ps}
    res = report_mod.render(args.results, args.out, target=args.target, model=args.model,
                            want_pdf=args.pdf, payload_texts=payload_texts)
    print(json.dumps(res, ensure_ascii=False, indent=2))


def add_filter_opts(sp):
    sp.add_argument("--payloads", nargs="*", help="payload JSONL 文件/目录/glob（默认 payloads/*.jsonl）")
    sp.add_argument("--category", help="按分类过滤")
    sp.add_argument("--objective", choices=["prompt_leak", "forbidden_action", "forbidden_probe", "both"])
    sp.add_argument("--severity", choices=["high", "medium", "low"])
    sp.add_argument("--tag", help="按标签过滤")
    sp.add_argument("--ids", help="只选指定 id，逗号分隔（复测/抽样用）")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="armor_tester", description="LLM 破甲测试器（授权端点自动化渗透）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("payloads", help="payload 库查看/统计")
    sp.add_argument("action", choices=["list", "stats", "show"])
    add_filter_opts(sp)
    sp.set_defaults(func=cmd_payloads)

    sp = sub.add_parser("import-goods", help="引入外部破甲词素材")
    sp.add_argument("--goods-root", default=r"D:\PROMPTS", help="素材根目录（默认 D:\\PROMPTS）")
    sp.add_argument("--out", default="payloads/payloads_ref.jsonl")
    sp.add_argument("--dedupe", action="store_true", help="追加并跳过已存在 id")
    sp.set_defaults(func=cmd_import_goods)

    sp = sub.add_parser("run", help="批量执行并落 CSV")
    add_filter_opts(sp)
    sp.add_argument("--limit", type=int, help="只跑前 N 条")
    sp.add_argument("--base-url", default=os.environ.get("ARMOR_BASE_URL"), help="OpenAI 兼容 base url，如 http://TARGET:PORT/v1")
    sp.add_argument("--api-key", default=None, help="API key（默认读 ARMOR_API_KEY）")
    sp.add_argument("--model", default="gpt-4o-mini", help="目标模型名")
    sp.add_argument("--system-file", help="目标已知 system prompt 文本（用于泄露判定）")
    sp.add_argument("--system-message", help="作为 system 消息注入（自建靶场）")
    sp.add_argument("--out", default="results/results.csv", help="结果 CSV 路径")
    sp.add_argument("--concurrency", type=int, default=8)
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--retries", type=int, default=2)
    sp.add_argument("--temperature", type=float, default=0.7)
    sp.add_argument("--max-tokens", type=int, default=1024)
    sp.add_argument("--repeat", type=int, default=1, help="每条 payload 采样次数（概率破防统计）")
    sp.add_argument("--qps", type=float, default=0, help="全局限速（每秒请求数，0=不限）")
    sp.add_argument("--carrier", choices=sorted(CARRIERS.keys()), default="none",
                    help="间接注入载体：email/webpage/tooldoc/code_comment/log/json_field")
    sp.add_argument("--resume", action="store_true", help="断点续作：跳过 CSV 中已完成的 payload")
    sp.add_argument("--dry-run", action="store_true", help="不发请求，只写 CSV 骨架")
    sp.add_argument("--analyze", action="store_true", help="跑完自动生成破防过程深度分析报告")
    sp.add_argument("--analyst-model", default="", help="分析报告用的 LLM 分析师模型（留空=纯规则）")
    sp.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验")
    sp.add_argument("--no-proxy", action="store_true", help="直连，忽略 HTTP(S)_PROXY 环境变量")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("judge", help="结果二次判定（规则/模型 judge）")
    sp.add_argument("--results", required=True)
    sp.add_argument("--out", default="results/results.judged.csv")
    sp.add_argument("--mode", choices=["rule", "model", "both"], default="rule")
    sp.add_argument("--base-url", default=os.environ.get("ARMOR_BASE_URL"))
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--judge-model", default="gpt-4o-mini")
    sp.add_argument("--system-file", help="已知 system prompt（泄露判定）")
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--no-proxy", action="store_true", help="直连，忽略 HTTP(S)_PROXY 环境变量")
    add_filter_opts(sp)
    sp.set_defaults(func=cmd_judge)

    sp = sub.add_parser("report", help="生成渗透报告")
    sp.add_argument("--results", required=True)
    sp.add_argument("--out", default="reports/report.md")
    sp.add_argument("--target", default="TARGET")
    sp.add_argument("--model", default="MODEL")
    sp.add_argument("--pdf", action="store_true", help="附带生成 PDF（需 weasyprint）")
    add_filter_opts(sp)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("chains", help="多轮攻击链编排（状态机式 n 轮对话）")
    sp.add_argument("--chains", default="payloads/chains.jsonl")
    sp.add_argument("--base-url", default=os.environ.get("ARMOR_BASE_URL"))
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--model", default="gpt-4o-mini")
    sp.add_argument("--system-file", help="已知 system prompt（泄露判定）")
    sp.add_argument("--out", default="results/chains.csv")
    sp.add_argument("--concurrency", type=int, default=4)
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--retries", type=int, default=1)
    sp.add_argument("--temperature", type=float, default=0.7)
    sp.add_argument("--max-tokens", type=int, default=1024)
    sp.add_argument("--resume", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--insecure", action="store_true")
    sp.add_argument("--no-proxy", action="store_true", help="直连，忽略 HTTP(S)_PROXY 环境变量")
    sp.set_defaults(func=cmd_chains)

    sp = sub.add_parser("expand", help="变异增殖：payload 库扩到 500+")
    add_filter_opts(sp)
    sp.add_argument("--target", type=int, default=600, help="目标总条数")
    sp.add_argument("--seed", type=int, default=13)
    sp.add_argument("--carrier", choices=sorted(CARRIERS.keys()), default="none")
    sp.add_argument("--prefix", default="M")
    sp.add_argument("--out", default="payloads/payloads_mutated.jsonl")
    sp.set_defaults(func=cmd_expand)

    sp = sub.add_parser("evolve", help="进化引擎：自动发现新越狱载荷")
    add_filter_opts(sp)
    sp.add_argument("--base-url", default=os.environ.get("ARMOR_BASE_URL"))
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--model", default="gpt-4o-mini")
    sp.add_argument("--gens", type=int, default=3, help="进化代数")
    sp.add_argument("--pop", type=int, default=20, help="种群大小")
    sp.add_argument("--elite", type=int, default=5, help="精英保留数")
    sp.add_argument("--seed", type=int, default=42)
    sp.add_argument("--carrier", choices=sorted(CARRIERS.keys()), default="none")
    sp.add_argument("--repeat", type=int, default=1)
    sp.add_argument("--concurrency", type=int, default=8)
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--retries", type=int, default=1)
    sp.add_argument("--temperature", type=float, default=0.9)
    sp.add_argument("--max-tokens", type=int, default=1024)
    sp.add_argument("--system-file", help="已知 system prompt（泄露判定）")
    sp.add_argument("--insecure", action="store_true")
    sp.add_argument("--no-proxy", action="store_true", help="直连，忽略 HTTP(S)_PROXY 环境变量")
    sp.add_argument("--out-dir", default="results/evolve")
    sp.set_defaults(func=cmd_evolve)

    sp = sub.add_parser("scan", help="全托管：一条命令跑完 全流程并自动出报告+深度分析")
    sp.add_argument("--profile", help="配置档案名（profiles.json，先 wizard 创建）")
    sp.add_argument("--base-url", default=None)
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--model", default=None, help="被测模型名")
    sp.add_argument("--analyst-model", default=None, help="分析用模型（回车/留空=规则版分析）")
    sp.add_argument("--system-file", default=None, help="已知 system prompt（泄露比对）")
    sp.add_argument("--intensity", choices=["quick", "standard", "full"], default=None,
                    help="quick=20条摸底 standard=93条(默认) full=693条")
    sp.add_argument("--repeat", type=int, default=None, help="采样次数（默认按强度）")
    sp.add_argument("--qps", type=float, default=None, help="限速（默认 2）")
    sp.add_argument("--concurrency", type=int, default=4)
    sp.add_argument("--timeout", type=float, default=180)
    sp.add_argument("--max-tokens", type=int, default=1024)
    sp.add_argument("--temperature", type=float, default=0.7)
    sp.add_argument("--tag", default=None, help="产物文件名前缀（默认时间戳）")
    sp.add_argument("--out-dir", default="results")
    sp.add_argument("--rep-dir", default="reports")
    sp.add_argument("--ids", default=None, help="只测指定载荷 id")
    sp.add_argument("--no-carrier", action="store_true", help="跳过间接注入载体段")
    sp.add_argument("--no-chains", action="store_true", help="跳过多轮攻击链段")
    sp.add_argument("--judge-mode", choices=["rule", "both"], default="rule")
    sp.add_argument("--top", type=int, default=8, help="深度分析条数")
    sp.add_argument("--no-pdf", action="store_true")
    sp.add_argument("--fresh", action="store_true", help="不续作，全部重跑")
    sp.add_argument("--insecure", action="store_true")
    sp.add_argument("--no-proxy", action="store_true", default=True,
                    help="直连（默认开启，忽略 HTTP(S)_PROXY）")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("wizard", help="交互向导：问几个问题就开跑（新手入口）")
    sp.set_defaults(func=cmd_wizard)

    sp = sub.add_parser("profiles", help="配置档案管理")
    sp.add_argument("action", choices=["list", "show", "delete"])
    sp.add_argument("name", nargs="?", default="")
    sp.set_defaults(func=cmd_profiles)

    sp = sub.add_parser("diff", help="回归对比：两份结果 CSV 差分")
    sp.add_argument("--old", required=True, help="基线结果 CSV（修复前/端点A）")
    sp.add_argument("--new", required=True, help="对比结果 CSV（修复后/端点B）")
    sp.add_argument("--out", default="reports/regression.md")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("analyze", help="破防过程深度分析报告（攻击链分解/防线失效矩阵/修复路线图）")
    sp.add_argument("--results", nargs="+", required=True, help="一份或多份结果 CSV")
    sp.add_argument("--out", default="reports/analysis.md")
    sp.add_argument("--target", default="TARGET")
    sp.add_argument("--model", default="MODEL", help="被测模型名（报告标签）")
    sp.add_argument("--analyst-model", default="", help="LLM 分析师模型（留空=纯规则分析）")
    sp.add_argument("--base-url", default=os.environ.get("ARMOR_BASE_URL"))
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--timeout", type=float, default=120)
    sp.add_argument("--no-proxy", action="store_true")
    sp.add_argument("--top", type=int, default=8, help="深度分析的破防样本数")
    sp.add_argument("--pdf", action="store_true")
    add_filter_opts(sp)
    sp.set_defaults(func=cmd_analyze)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
