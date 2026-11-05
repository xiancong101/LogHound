"""Nginx access log（combined 格式）解析器。

示例行：:

    127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] "GET /admin.php HTTP/1.1" 404 162 "-" "sqlmap/1.7"

combined 格式标准字段：
    ``$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"``
"""

from __future__ import annotations

import re
from typing import Any

from .base import LOG_TYPE_NGINX, make_event, to_int, to_iso8601

# 主通道正则：匹配 combined 格式访问日志。
# 分组说明（按括号顺序）：
#   1. ip        —— 客户端 IP（$remote_addr）
#   2. time      —— 时间，如 12/Mar/2025:10:23:45（+0800 时区忽略）
#   3. method    —— 请求方法，如 GET
#   4. path      —— 请求路径，如 /admin.php
#   5. status    —— HTTP 状态码，如 404
#   6. size      —— 响应体大小（$body_bytes_sent，- 表示 0/未知）
#   7. ua        —— User-Agent（引号内）
_MAIN_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)


def parse_nginx(line: str) -> dict[str, Any] | None:
    """把一行 Nginx combined 访问日志解析为统一事件 dict。

    主通道用预编译正则；失配时回退到分隔符切分；仍失败返回 None。
    """
    raw = line.rstrip("\n")

    # —— 主通道：正则 ——
    m = _MAIN_RE.match(raw)
    if m is not None:
        ts = to_iso8601(m.group("time"))
        if ts is not None:
            return make_event(
                ts=ts,
                ip=m.group("ip"),
                method=m.group("method"),
                path=m.group("path"),
                status=to_int(m.group("status")),
                size=to_int(m.group("size")),
                ua=m.group("ua") or None,
                raw=raw,
                log_type=LOG_TYPE_NGINX,
            )
        # 时间解析失败也走备通道，避免主通道半途失效

    # —— 备通道：分隔符切分 ——
    return _parse_nginx_by_split(raw)


def _parse_nginx_by_split(raw: str) -> dict[str, Any] | None:
    """分隔符切分兜底：按结构定位关键字段，不依赖固定索引。

    由于 ``[12/Mar/2025:10:23:45 +0800]`` 中的空格会被 ``split()`` 拆开，
    这里改用结构驱动的方式：IP 取首个 token；时间用正则从方括号中抓取；
    请求方法/路径/状态码/大小按引号与空白定位；UA 取最后一个引号字段。
    """
    ip = raw.split(maxsplit=1)[0] if raw.strip() else None
    if ip is None:
        return None

    # 时间：抓取方括号内的内容
    time_m = re.search(r"\[([^\]]+)\]", raw)
    if time_m is None:
        return None
    ts = to_iso8601(time_m.group(1))
    if ts is None:
        return None

    # 请求行：抓取第一个引号内的 "METHOD PATH PROTO"
    req_m = re.search(r'"([A-Z]+)\s+(\S+)\s+HTTP/\S+"', raw)
    method = req_m.group(1) if req_m else None
    path = req_m.group(2) if req_m else None

    # 状态码与大小：请求行之后紧随的两个数字字段
    tail = raw[req_m.end():] if req_m else raw
    num_m = re.search(r'(\d{3})\s+(\d+|-)\b', tail)
    status = to_int(num_m.group(1)) if num_m else None
    size = to_int(num_m.group(2)) if num_m else None

    # UA：最后一个引号包裹的字段
    ua_m = re.search(r'"([^"]*)"\s*$', raw)
    ua = ua_m.group(1) or None if ua_m else None

    return make_event(
        ts=ts,
        ip=ip,
        method=method,
        path=path,
        status=status,
        size=size,
        ua=ua,
        raw=raw,
        log_type=LOG_TYPE_NGINX,
    )
