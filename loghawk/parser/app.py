"""通用应用日志（JSON 行格式）解析器。

示例行：:

    {"time":"2025-03-12T10:23:45","ip":"10.0.0.5","path":" /login","status":401,"msg":"bad password"}

JSON 行（JSONL）即每行一个 JSON 对象。字段名不固定，
解析时按常见键名（time/ip/method/path/status/size/ua）抽取，
并对齐到统一输出格式。
"""

from __future__ import annotations

import json
from typing import Any

from .base import LOG_TYPE_APP, make_event, to_int, to_iso8601

# 主通道：把整行 JSON 字符串直接解析为 dict（无需正则）。
# 键名映射：把应用日志里可能出现的字段名归一化到标准字段。
_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("time", "timestamp", "ts", "@timestamp"),
    "ip": ("ip", "remote_addr", "client_ip", "src_ip"),
    "method": ("method", "request_method", "verb"),
    "path": ("path", "url", "uri", "request_path"),
    "status": ("status", "status_code", "code"),
    "size": ("size", "bytes", "body_bytes_sent"),
    "ua": ("ua", "user_agent", "useragent"),
}


def _pick(obj: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    """按别名优先级从 JSON 对象中取第一个存在的值。"""
    for key in aliases:
        if key in obj:
            return obj[key]
    return None


def parse_app(line: str) -> dict[str, Any] | None:
    """把一行 JSON 应用日志解析为统一事件 dict。

    主通道：整行 ``json.loads`` 解析；失配（非 JSON / 字段缺失）时
    回退到分隔符切分；仍失败返回 None。
    """
    raw = line.rstrip("\n")

    # —— 主通道：JSON 解析 ——
    obj = _try_loads(raw)
    if obj is not None:
        ts_raw = _pick(obj, _KEY_ALIASES["ts"])
        ts = to_iso8601(str(ts_raw)) if ts_raw is not None else None
        # JSON 主通道要求至少能解析出时间，否则视为失配走备通道
        if ts is not None:
            return make_event(
                ts=ts,
                ip=_as_str(_pick(obj, _KEY_ALIASES["ip"])),
                method=_as_str(_pick(obj, _KEY_ALIASES["method"])),
                path=_as_str(_pick(obj, _KEY_ALIASES["path"])),
                status=to_int(_pick(obj, _KEY_ALIASES["status"])),
                size=to_int(_pick(obj, _KEY_ALIASES["size"])),
                ua=_as_str(_pick(obj, _KEY_ALIASES["ua"])),
                raw=raw,
                log_type=LOG_TYPE_APP,
            )

    # —— 备通道：分隔符切分 ——
    return _parse_app_by_split(raw)


def _parse_app_by_split(raw: str) -> dict[str, Any] | None:
    """分隔符切分兜底：对 ``key=value`` 或 ``key:value`` 风格的行提取字段。"""
    tokens = raw.split()
    fields: dict[str, Any] = {}
    for tok in tokens:
        for sep in ("=", ":"):
            if sep in tok:
                k, _, v = tok.partition(sep)
                fields[k] = v
                break

    if not fields:
        return None

    ts_raw = _pick(fields, _KEY_ALIASES["ts"])
    ts = to_iso8601(str(ts_raw)) if ts_raw is not None else None
    if ts is None:
        return None

    return make_event(
        ts=ts,
        ip=_as_str(_pick(fields, _KEY_ALIASES["ip"])),
        method=_as_str(_pick(fields, _KEY_ALIASES["method"])),
        path=_as_str(_pick(fields, _KEY_ALIASES["path"])),
        status=to_int(_pick(fields, _KEY_ALIASES["status"])),
        size=to_int(_pick(fields, _KEY_ALIASES["size"])),
        ua=_as_str(_pick(fields, _KEY_ALIASES["ua"])),
        raw=raw,
        log_type=LOG_TYPE_APP,
    )


def _try_loads(text: str) -> dict[str, Any] | None:
    """安全地 ``json.loads``，失败返回 None 而不抛异常。"""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _as_str(value: Any) -> str | None:
    """把值安全转成字符串；空值返回 None。"""
    if value is None:
        return None
    text = str(value)
    return text if text else None
