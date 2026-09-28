"""payload 库加载器：JSONL 多文件加载、校验、筛选、统计。"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field

VALID_OBJECTIVES = {"prompt_leak", "forbidden_action", "both", "forbidden_probe"}
VALID_SEVERITY = {"high", "medium", "low"}


@dataclass
class Payload:
    id: str
    name: str
    category: str
    severity: str
    objective: str
    payload: str
    tags: list = field(default_factory=list)
    leak_markers: list = field(default_factory=list)
    canary: str | None = None
    system_prompt_override: str | None = None
    follow_up: str | None = None   # 多轮攻击链：首轮回答后的触发消息
    parent_id: str | None = None   # 血缘：由哪个 payload 变异而来
    source: str = "builtin"
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Payload":
        missing = [k for k in ("id", "name", "category", "severity", "objective", "payload") if not d.get(k)]
        if missing:
            raise ValueError(f"payload 记录缺少字段 {missing}: {d.get('id', '<no id>')}")
        if d["objective"] not in VALID_OBJECTIVES:
            raise ValueError(f"{d['id']}: objective 非法 {d['objective']!r}")
        if d["severity"] not in VALID_SEVERITY:
            raise ValueError(f"{d['id']}: severity 非法 {d['severity']!r}")
        return cls(
            id=str(d["id"]),
            name=str(d["name"]),
            category=str(d["category"]),
            severity=str(d["severity"]),
            objective=str(d["objective"]),
            payload=str(d["payload"]),
            tags=list(d.get("tags") or []),
            leak_markers=[str(x) for x in (d.get("leak_markers") or [])],
            canary=d.get("canary"),
            system_prompt_override=d.get("system_prompt_override"),
            follow_up=d.get("follow_up"),
            parent_id=d.get("parent_id"),
            source=str(d.get("source") or "builtin"),
            notes=str(d.get("notes") or ""),
        )

    def canaries(self) -> list[str]:
        """payload 自带的服从标记；字段为空时从正文提取 [[OBEYED-*]]。"""
        if self.canary:
            return [self.canary]
        import re
        return re.findall(r"\[\[OBEYED-[A-Z0-9\-]+\]\]", self.payload)


def expand_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, "*.jsonl"))))
        else:
            hits = sorted(glob.glob(p))
            out.extend(hits if hits else [p])
    seen, uniq = set(), []
    for p in out:
        rp = os.path.abspath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def load_payloads(paths: list[str]) -> list[Payload]:
    """从一个或多个 JSONL 文件加载 payload，id 全局唯一。"""
    payloads: list[Payload] = []
    by_id: dict[str, str] = {}
    for path in expand_paths(paths):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"payload 文件不存在: {path}")
        with open(path, "r", encoding="utf-8") as f:
            for ln, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{path}:{ln} JSON 解析失败: {e}") from e
                p = Payload.from_dict(d)
                if p.id in by_id:
                    raise ValueError(f"payload id 重复: {p.id} ({by_id[p.id]} 与 {path}:{ln})")
                by_id[p.id] = f"{path}:{ln}"
                payloads.append(p)
    return payloads


def filter_payloads(payloads: list[Payload], category: str | None = None,
                    objective: str | None = None, severity: str | None = None,
                    tag: str | None = None, ids: str | None = None) -> list[Payload]:
    out = payloads
    if category:
        out = [p for p in out if p.category == category]
    if objective:
        want = {"prompt_leak", "forbidden_action"} if objective == "both" else {objective}
        out = [p for p in out if p.objective in want or p.objective == "both"]
    if severity:
        out = [p for p in out if p.severity == severity]
    if tag:
        out = [p for p in out if tag in p.tags]
    if ids:
        want_ids = {x.strip() for x in ids.split(",") if x.strip()}
        out = [p for p in out if p.id in want_ids]
    return out


def stats(payloads: list[Payload]) -> dict:
    def count(key):
        d: dict[str, int] = {}
        for p in payloads:
            v = getattr(p, key)
            d[v] = d.get(v, 0) + 1
        return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0])))
    return {
        "total": len(payloads),
        "by_category": count("category"),
        "by_severity": count("severity"),
        "by_objective": count("objective"),
        "by_source": count("source"),
    }
