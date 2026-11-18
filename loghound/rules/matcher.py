"""规则的 match 条件和聚合键提取。

match 里所有字段同时满足才算命中（AND）；status / method 传列表时列表内部是 OR。
"""

from __future__ import annotations

import time
from typing import Any

from .models import Rule


def match_rule(rule: Rule, event: dict[str, Any]) -> bool:
    """事件是否满足规则的门槛条件。"""
    m = rule.match

    if m.log_type is not None and event.get("log_type") != m.log_type:
        return False

    # status / method 传的是列表，命中其中之一即可
    if m.status is not None and event.get("status") not in m.status:
        return False

    if m.method is not None and event.get("method") not in m.method:
        return False

    if rule.compiled_path is not None:
        if rule.compiled_path.search(event.get("path") or "") is None:
            return False

    if rule.compiled_ua is not None:
        if rule.compiled_ua.search(event.get("ua") or "") is None:
            return False

    if m.min_size is not None:
        size = event.get("size")
        if size is None or size < m.min_size:
            return False

    return True


def extract_group_key(rule: Rule, event: dict[str, Any]) -> str:
    """按 window.group_by 取聚合键。未知维度按 ip 处理。"""
    gb = rule.window.group_by
    if gb == "ip":
        return str(event.get("ip") or "unknown")
    if gb == "ip+path":
        return f"{event.get('ip') or 'unknown'}|{event.get('path') or ''}"
    if gb == "ua":
        return str(event.get("ua") or "unknown")
    if gb == "path":
        return str(event.get("path") or "")
    if gb == "none":
        return "__all__"
    return str(event.get("ip") or "unknown")


def event_timestamp(event: dict[str, Any]) -> float:
    """把事件的 ISO8601 ts 转成 epoch 秒。转不动就用当前时间，别让流程断在这。"""
    ts = event.get("ts")
    if isinstance(ts, str):
        try:
            return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, OverflowError):
            pass
    return time.time()
