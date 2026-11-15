"""显示过滤器：一个小型的、带优先级与括号的布尔表达式求值器。

支持语法（大小写不敏感）::

    http and tcp.port == 80
    (tcp or udp) and not port 22
    ip.addr == 192.168.1.10 and frame.len > 100
    http.host contains "example"
    dns.qry.name matches "^www\\.google\\.com$"

运算符优先级：``not`` > ``and`` > ``or``，括号可改变结合顺序。
这即是实验中要求的“协议过滤器支持逻辑演算”，过滤器本身是一个
词法→语法→求值三段式的解释器，与 libpcap 的 BPF 编译器思路一致。
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from .models import PacketRecord


class FilterSyntaxError(ValueError):
    pass


# ---------------------------------------------------------------- 词法分析

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<LPAREN>\() |
        (?P<RPAREN>\)) |
        (?P<OP><=|>=|==|!=|=~|~|<|>) |
        (?P<STRING>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*') |
        (?P<ADDR>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}) |
        (?P<NUMBER>\d+(?:\.\d+)?) |
        (?P<IDENT>[A-Za-z_][A-Za-z0-9_.\-]*) |
        (?P<RAW>.)
    )
    """,
    re.VERBOSE,
)

_KEYWORDS = {
    "and": "AND", "or": "OR", "not": "NOT", "&&": "AND", "||": "OR", "!": "NOT",
    "contains": "OP", "matches": "OP", "eq": "OP", "ne": "OP",
}


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match:
            break
        pos = match.end()
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "RAW":
            if value.strip() == "":
                continue
            raise FilterSyntaxError(f"无法识别的字符：{value!r}")
        if kind == "IDENT" and value.lower() in _KEYWORDS:
            tokens.append((_KEYWORDS[value.lower()], value.lower()))
        elif kind == "OP":
            mapped = {"=": "==", "~": "matches", "=~": "matches",
                      "eq": "==", "ne": "!="}.get(value, value)
            tokens.append(("OP", mapped))
        elif kind == "STRING":
            body = value[1:-1]
            body = re.sub(r"\\(.)", r"\1", body)
            tokens.append(("STRING", body))
        elif kind == "NUMBER":
            tokens.append(("NUMBER", value))
        elif kind == "ADDR":
            tokens.append(("IDENT", value))
        elif kind == "LPAREN":
            tokens.append(("LPAREN", value))
        elif kind == "RPAREN":
            tokens.append(("RPAREN", value))
        else:
            tokens.append(("IDENT", value))
    return tokens


# ---------------------------------------------------------------- 字段取值

def _http(rec: PacketRecord) -> dict[str, Any]:
    return (rec.app or {}).get("http") or {}


def _dns(rec: PacketRecord) -> dict[str, Any]:
    return (rec.app or {}).get("dns") or {}


def _tls(rec: PacketRecord) -> dict[str, Any]:
    return (rec.app or {}).get("tls") or {}


def _tcp_len(rec: PacketRecord) -> int:
    for name in ("tcp",):
        if name in rec.layers:
            # 由 caplen 估计：链路+IP 头长度未知时退化为 0，仅用于粗筛
            return max(0, rec.length - 54)
    return 0


FIELD_GETTERS: dict[str, Callable[[PacketRecord], Any]] = {
    "frame.number": lambda r: r.index,
    "frame.len": lambda r: r.length,
    "frame.time": lambda r: r.ts,
    "len": lambda r: r.length,
    "length": lambda r: r.length,
    "ip.src": lambda r: r.src if "ip" in r.layers or "ipv6" in r.layers else None,
    "ip.dst": lambda r: r.dst if "ip" in r.layers or "ipv6" in r.layers else None,
    "ip.addr": lambda r: (r.src, r.dst) if "ip" in r.layers or "ipv6" in r.layers else None,
    "ipv6.src": lambda r: r.src if "ipv6" in r.layers else None,
    "ipv6.dst": lambda r: r.dst if "ipv6" in r.layers else None,
    "tcp.srcport": lambda r: r.sport if "tcp" in r.layers else None,
    "tcp.dstport": lambda r: r.dport if "tcp" in r.layers else None,
    "tcp.port": lambda r: (r.sport, r.dport) if "tcp" in r.layers else None,
    "tcp.len": _tcp_len,
    "udp.srcport": lambda r: r.sport if "udp" in r.layers else None,
    "udp.dstport": lambda r: r.dport if "udp" in r.layers else None,
    "udp.port": lambda r: (r.sport, r.dport) if "udp" in r.layers else None,
    "eth.src": lambda r: r.src_mac or None,
    "eth.dst": lambda r: r.dst_mac or None,
    "protocol": lambda r: r.proto,
    "proto": lambda r: r.proto,
    "info": lambda r: r.info,
    "http.host": lambda r: _http(r).get("header_map", {}).get("host"),
    "http.request.method": lambda r: _http(r).get("method"),
    "http.request.uri": lambda r: _http(r).get("uri"),
    "http.response.code": lambda r: _http(r).get("status"),
    "http.user_agent": lambda r: _http(r).get("header_map", {}).get("user-agent"),
    "dns.qry.name": lambda r: _dns(r).get("qname") or None,
    "tls.sni": lambda r: _tls(r).get("sni"),
    "proc.name": lambda r: r.pname or None,
    "proc.pid": lambda r: r.pid,
}

_PROTO_KEYWORDS = {
    "tcp", "udp", "icmp", "icmpv6", "arp", "ip", "ipv4", "ipv6", "dns", "http",
    "tls", "ssl", "dhcp", "ssh", "ntp", "ftp", "smtp", "telnet", "smb", "quic",
}


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"-?\d+", text):
            return float(int(text))
        if re.fullmatch(r"-?\d+\.\d+", text):
            return float(text)
    return None


# ---------------------------------------------------------------- 语法分析

class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> Optional[tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError("表达式意外结束")
        self.pos += 1
        return token

    def _expect(self, kind: str) -> tuple[str, str]:
        token = self._next()
        if token[0] != kind:
            raise FilterSyntaxError(f"期望 {kind}，实际得到 {token[1]!r}")
        return token

    def parse(self) -> Any:
        if not self.tokens:
            raise FilterSyntaxError("过滤器为空")
        node = self._parse_or()
        if self._peek() is not None:
            raise FilterSyntaxError(f"多余的内容：{self._peek()[1]!r}")
        return node

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while self._peek() and self._peek()[0] == "OR":
            self._next()
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_unary()
        while self._peek() and self._peek()[0] == "AND":
            self._next()
            node = ("and", node, self._parse_unary())
        return node

    def _parse_unary(self) -> Any:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError("表达式不完整")
        if token[0] == "NOT":
            self._next()
            return ("not", self._parse_unary())
        if token[0] == "LPAREN":
            self._next()
            node = self._parse_or()
            self._expect("RPAREN")
            return node
        return self._parse_predicate()

    def _parse_predicate(self) -> Any:
        kind, value = self._next()
        if kind not in ("IDENT", "NUMBER", "STRING"):
            raise FilterSyntaxError(f"此处不允许 {value!r}")

        lowered = value.lower()

        # 形如 "port 80" / "src host 1.2.3.4" / "dst port 443"
        if kind == "IDENT" and lowered in ("src", "dst"):
            direction = lowered
            nxt = self._next()
            if nxt[0] != "IDENT" or nxt[1].lower() not in ("port", "host"):
                raise FilterSyntaxError(f"src/dst 后应为 port 或 host，实际为 {nxt[1]!r}")
            target = nxt[1].lower()
            operand = self._next()
            return ("dir", direction, target, operand[1])

        if kind == "IDENT" and lowered == "port":
            operand = self._next()
            return ("port", operand[1])

        if kind == "IDENT" and lowered == "host":
            operand = self._next()
            return ("host", operand[1])

        peek = self._peek()
        if kind == "IDENT" and peek and peek[0] == "OP":
            self._next()
            operand = self._next()
            if operand[0] not in ("NUMBER", "STRING", "IDENT"):
                raise FilterSyntaxError(f"运算符后缺少取值：{operand[1]!r}")
            return ("cmp", lowered, peek[1], operand[1])

        if kind == "IDENT" and peek and peek[0] == "IDENT" and lowered in ("frame", "tcp", "udp", "ip", "http", "dns"):
            # 允许 "frame contains abc" 之类的写法
            op = self._next()
            operand = self._next()
            if op[1].lower() not in ("contains", "matches"):
                raise FilterSyntaxError(f"不支持的关键字组合：{lowered} {op[1]}")
            return ("cmp", lowered, op[1].lower(), operand[1])

        if kind == "IDENT" and lowered in _PROTO_KEYWORDS:
            return ("proto", lowered)

        if kind == "IDENT" and lowered in FIELD_GETTERS:
            return ("field", lowered)

        raise FilterSyntaxError(f"无法解析的过滤器片段：{value!r}")


# ---------------------------------------------------------------- 求值

def _compare(left: Any, op: str, right_text: str) -> bool:
    if left is None:
        return False
    if isinstance(left, (tuple, list)):
        return any(_compare(item, op, right_text) for item in left)

    if op == "contains":
        return right_text.lower() in str(left).lower()
    if op == "matches":
        try:
            return re.search(right_text, str(left), re.IGNORECASE) is not None
        except re.error as exc:
            raise FilterSyntaxError(f"正则表达式非法：{exc}") from exc

    left_num = _as_number(left)
    right_num = _as_number(right_text)

    if op in ("==", "!=") and (left_num is None or right_num is None):
        equal = str(left).strip().lower() == str(right_text).strip().lower()
        return equal if op == "==" else not equal

    if left_num is None or right_num is None:
        raise FilterSyntaxError(f"无法比较 {left!r} 与 {right_text!r}")

    if op == "==":
        return left_num == right_num
    if op == "!=":
        return left_num != right_num
    if op == ">":
        return left_num > right_num
    if op == "<":
        return left_num < right_num
    if op == ">=":
        return left_num >= right_num
    if op == "<=":
        return left_num <= right_num
    raise FilterSyntaxError(f"未知运算符：{op}")


def _evaluate(node: Any, rec: PacketRecord) -> bool:
    kind = node[0]
    if kind == "and":
        return _evaluate(node[1], rec) and _evaluate(node[2], rec)
    if kind == "or":
        return _evaluate(node[1], rec) or _evaluate(node[2], rec)
    if kind == "not":
        return not _evaluate(node[1], rec)

    if kind == "proto":
        keyword = node[1]
        if keyword in ("ipv4",):
            keyword = "ip"
        if keyword in ("ssl",):
            keyword = "tls"
        if keyword in ("quic",):
            return "udp" in rec.layers and rec.dport == 443
        if keyword in rec.layers:
            return True
        proto_lower = rec.proto.lower()
        return proto_lower == keyword or (keyword == "tls" and proto_lower in ("https", "tls"))

    if kind == "field":
        return FIELD_GETTERS[node[1]](rec) is not None

    if kind == "cmp":
        getter = FIELD_GETTERS.get(node[1])
        if getter is None:
            raise FilterSyntaxError(f"未知字段：{node[1]}")
        return _compare(getter(rec), node[2], node[3])

    if kind == "port":
        number = _as_number(node[1])
        return number is not None and number in (rec.sport, rec.dport)

    if kind == "host":
        target = node[1].lower()
        return target in (rec.src.lower(), rec.dst.lower())

    if kind == "dir":
        direction, target_kind, operand = node[1], node[2], node[3]
        if target_kind == "port":
            number = _as_number(operand)
            if number is None:
                return False
            return number == (rec.sport if direction == "src" else rec.dport)
        value = rec.src if direction == "src" else rec.dst
        return value.lower() == operand.lower()

    raise FilterSyntaxError(f"未知节点：{kind}")


class DisplayFilter:
    """编译后的显示过滤器。空表达式表示“全部通过”。"""

    __slots__ = ("text", "_ast", "_empty")

    def __init__(self, text: str = ""):
        self.text = (text or "").strip()
        self._empty = not self.text
        if self._empty:
            self._ast = None
        else:
            self._ast = _Parser(_tokenize(self.text)).parse()

    @property
    def is_empty(self) -> bool:
        return self._empty

    def match(self, record: PacketRecord) -> bool:
        if self._empty:
            return True
        return _evaluate(self._ast, record)


def validate(text: str) -> Optional[str]:
    """校验过滤器语法，返回错误信息；None 表示合法。"""
    try:
        DisplayFilter(text)
    except FilterSyntaxError as exc:
        return str(exc)
    return None
