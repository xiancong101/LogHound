"""规则匹配器：判断单个事件是否满足规则的门槛条件，并提取聚合键。

门槛条件（``rule.match``）为「全部满足才命中」的 AND 语义：
    - ``log_type``：事件类型精确相等（可选）
    - ``status``：事件状态码在列表中（列表为 OR 语义，可选）
    - ``method``：请求方法在列表中（可选）
    - ``path_regex`` / ``ua_regex``：正则命中（可选）
    - ``min_size``：响应体大小 >= 阈值（可选）

事件输入为 parser 模块产出的统一 dict（见 ``loghound.parser``）。
"""

from __future__ import annotations

import time
from typing import Any

from .models import Rule


def match_rule(rule: Rule, event: dict[str, Any]) -> bool:
    """判断事件是否命中规则的门槛条件（全部满足返回 True）。"""
    m = rule.match

    # log_type 精确相等
    if m.log_type is not None and event.get("log_type") != m.log_type:
        return False

    # status 列表命中（OR）
    if m.status is not None:
        if event.get("status") not in m.status:
            return False

    # method 列表命中
    if m.method is not None:
        if event.get("method") not in m.method:
            return False

    # path 正则命中
    if rule.compiled_path is not None:
        path = event.get("path") or ""
        if rule.compiled_path.search(path) is None:
            return False

    # UA 正则命中
    if rule.compiled_ua is not None:
        ua = event.get("ua") or ""
        if rule.compiled_ua.search(ua) is None:
            return False

    # 最小体积阈值
    if m.min_size is not None:
        size = event.get("size")
        if size is None or size < m.min_size:
            return False

    return True


def extract_group_key(rule: Rule, event: dict[str, Any]) -> str:
    """按规则的 ``window.group_by`` 提取聚合键。

    支持维度：
        - ``ip``：来源 IP
        - ``ip+path``：IP 与路径组合
        - ``ua``：User-Agent
        - ``path``：请求路径
        - ``none``：全局聚合（所有事件归入同一键）
    """
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
    # 兜底：未知维度按 ip 处理
    return str(event.get("ip") or "unknown")


def event_timestamp(event: dict[str, Any]) -> float:
    """从事件提取时间戳（Unix 秒）。``ts`` 是 ISO8601 字符串。

    解析失败时回退到当前时间（保证检测流程不中断）。
    """
    ts = event.get("ts")
    if isinstance(ts, str):
        try:
            # ISO8601 字符串 -> epoch 秒
            return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, OverflowError):
            pass
    return time.time()
