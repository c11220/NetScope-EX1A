"""应用层识别与解析：HTTP、TLS（含 SNI）、DNS 名称。

抓包层次（NPS）只负责把帧抄下来；分析层次（NPA）才需要理解
“这串字节到底是什么应用层协议”。本模块即 NPA 的应用层部分。
"""

from __future__ import annotations

import re
from typing import Any, Optional

_HTTP_METHODS = (
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
    b"PATCH", b"TRACE", b"CONNECT",
)

_REQUEST_LINE = re.compile(rb"^([A-Z]+)\s+(\S+)\s+HTTP/(\d\.\d)\r?\n")
_STATUS_LINE = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})\s*([^\r\n]*)")
_HEADER_LINE = re.compile(rb"^([^:\r\n]+):\s*(.*)$")

_METHOD_TEXT = {m.decode(): m.decode() for m in _HTTP_METHODS}


def is_http_request(payload: bytes) -> bool:
    if not payload:
        return False
    head = payload[:8]
    for method in _HTTP_METHODS:
        if head.startswith(method) and b" " in payload[:16]:
            if b"HTTP/" in payload[:64] or method != b"GET":
                return True
    return False


def is_http_response(payload: bytes) -> bool:
    return payload[:5] == b"HTTP/"


def is_tls_record(payload: bytes) -> bool:
    """TLS 记录层：ContentType(1B) + Version(2B=0x0301~0x0304) + Length(2B)。"""
    if len(payload) < 5:
        return False
    if payload[0] not in (0x14, 0x15, 0x16, 0x17):
        return False
    if payload[1] != 0x03 or payload[2] > 0x04:
        return False
    return True


def _split_head_body(payload: bytes) -> tuple[list[bytes], bytes]:
    idx = payload.find(b"\r\n\r\n")
    sep = 4
    if idx < 0:
        idx = payload.find(b"\n\n")
        sep = 2
    if idx < 0:
        return payload.split(b"\r\n"), b""
    return payload[:idx].split(b"\r\n"), payload[idx + sep:]


def parse_http(payload: bytes) -> Optional[dict[str, Any]]:
    """解析一条完整的或部分 HTTP 报文头，返回结构化信息。"""
    if not payload:
        return None

    lines, body = _split_head_body(payload)
    if not lines:
        return None

    first = lines[0]
    headers: list[tuple[str, str]] = []
    result: dict[str, Any] = {"headers": headers, "body_len": len(body), "body": body}

    m = _REQUEST_LINE.match(first + b"\r\n")
    if m:
        result.update(
            type="request",
            method=m.group(1).decode("latin-1"),
            uri=m.group(2).decode("latin-1"),
            version=m.group(3).decode("latin-1"),
        )
    else:
        m = _STATUS_LINE.match(first)
        if not m:
            return None
        result.update(
            type="response",
            version=m.group(1).decode("latin-1"),
            status=int(m.group(2)),
            reason=m.group(3).decode("latin-1").strip(),
        )

    for raw_line in lines[1:]:
        hm = _HEADER_LINE.match(raw_line)
        if not hm:
            continue
        try:
            name = hm.group(1).decode("latin-1").strip()
            value = hm.group(2).decode("latin-1").strip()
        except Exception:
            continue
        headers.append((name, value))

    result["header_map"] = {k.lower(): v for k, v in headers}
    return result


def summarize_http(http: dict[str, Any]) -> str:
    hmap = http.get("header_map", {})
    if http.get("type") == "request":
        host = hmap.get("host", "")
        uri = http.get("uri", "")
        info = f"{http.get('method')} {uri} HTTP/{http.get('version')}"
        if host:
            info += f"  Host: {host}"
    else:
        info = f"HTTP/{http.get('version')} {http.get('status')} {http.get('reason', '')}".rstrip()
        ctype = hmap.get("content-type")
        if ctype:
            info += f"  ({ctype})"
    return info


def decode_domain(value: Any) -> str:
    """解码 DNS/TLS 中的域名，兼容 bytes 与 str。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.rstrip(".")
    try:
        return value.decode("idna").rstrip(".")
    except Exception:
        return value.decode("latin-1", "replace").rstrip(".")


def parse_tls_client_hello(payload: bytes) -> Optional[dict[str, Any]]:
    """从 TLS ClientHello 中提取 SNI（不解密任何内容）。"""
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        body_len = int.from_bytes(payload[3:5], "big")
        body = payload[5:5 + body_len]
        if len(body) < 4 or body[0] != 0x01:      # handshake type: client_hello
            return None
        # 跳过 handshake 头(4B) + version(2B) + random(32B)
        pos = 4 + 2 + 32
        sid_len = body[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + cs_len
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            data = body[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 0x0000 and len(data) >= 5:   # server_name
                listed = data[2:]
                name_type = listed[0]
                name_len = int.from_bytes(listed[1:3], "big")
                if name_type == 0:
                    return {"sni": decode_domain(listed[3:3 + name_len]),
                            "version": int.from_bytes(payload[9:11], "big")}
        return {"sni": None, "version": int.from_bytes(payload[9:11], "big")}
    except Exception:
        return None


_TLS_VERSIONS = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def tls_version_name(code: int) -> str:
    return _TLS_VERSIONS.get(code, f"0x{code:04x}")


def decode_text(data: bytes, limit: int = 4 * 1024 * 1024) -> str:
    """把字节流尽力解码为可读文本（供流追踪面板使用）。"""
    data = data[:limit]
    for encoding in ("utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")
