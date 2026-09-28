"""OpenAI 兼容 Chat Completions 客户端（纯标准库，零第三方依赖）。"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request


def extract_text(resp_json: dict) -> str:
    """兼容 content 为字符串或分段数组（如部分兼容网关）。"""
    try:
        content = resp_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        # 某些网关把文本放在 choices[0].text
        try:
            return str(resp_json["choices"][0].get("text", ""))
        except Exception:
            return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                parts.append(str(part.get("text", "")))
            else:
                parts.append(str(part))
        return "".join(parts)
    return str(content or "")


class ChatClient:
    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: float = 60.0, verify_ssl: bool = True,
                 extra_headers: dict | None = None, no_proxy: bool = False):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.model = model
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.extra_headers = extra_headers or {}
        self._ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        handlers = [urllib.request.HTTPSHandler(context=self._ctx)]
        if no_proxy:
            # 直连：绕过 HTTP(S)_PROXY 环境变量（本地网关/被代理劫持的内网端点）
            handlers.insert(0, urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def chat(self, messages: list[dict], temperature: float = 0.7,
             max_tokens: int = 1024, retries: int = 2,
             extra_body: dict | None = None) -> dict:
        """单次对话补全。返回 {ok, http_status, text, latency_ms, error?, raw?}"""
        url = self.base_url + "/chat/completions"
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if extra_body:
            body.update(extra_body)
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        last_err = ""
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            if self.api_key:
                req.add_header("Authorization", f"Bearer {self.api_key}")
            for k, v in self.extra_headers.items():
                req.add_header(k, v)
            t0 = time.time()
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                    resp_json = json.loads(raw)
                    return {
                        "ok": True,
                        "http_status": getattr(resp, "status", 200),
                        "text": extract_text(resp_json),
                        "latency_ms": int((time.time() - t0) * 1000),
                        "raw": resp_json,
                    }
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", "replace")
                last_err = f"HTTP {e.code}: {raw[:500]}"
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    time.sleep(1.2 * (attempt + 1))
                    continue
                return {"ok": False, "http_status": e.code, "text": "",
                        "latency_ms": int((time.time() - t0) * 1000), "error": last_err}
            except Exception as e:  # 网络层/解析层
                last_err = f"{type(e).__name__}: {e}"
                if attempt < retries:
                    time.sleep(1.2 * (attempt + 1))
                    continue
                return {"ok": False, "http_status": 0, "text": "",
                        "latency_ms": int((time.time() - t0) * 1000), "error": last_err}
        return {"ok": False, "http_status": 0, "text": "", "latency_ms": 0, "error": last_err}
