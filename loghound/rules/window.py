"""窗口统计与告警触发。

每个 (rule_id, group_value) 一个 WindowState，里面存命中时间戳的 deque。
sliding=true 时把早于 now-seconds 的从左边弹掉，长度就是窗口内命中数；
sliding=false 时按 floor(ts/seconds) 分片，跨片就清空。
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Any, Iterator, Optional

from .matcher import event_timestamp, extract_group_key, match_rule
from .models import Alert, Rule


def _iso_ts(ts: float) -> str:
    """把 Unix 秒转为 ISO8601 字符串（本地时区）。"""
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")


class WindowState:
    """(rule_id, group_value) 对应的一份窗口状态。"""

    __slots__ = ("rule_id", "group_value", "hits", "last_alert_ts", "fixed_bucket")

    def __init__(self, rule_id: str, group_value: str) -> None:
        self.rule_id = rule_id
        self.group_value = group_value
        self.hits: deque[float] = deque()      # 命中时间戳，滑动窗口靠它算数量
        self.last_alert_ts: float = 0.0        # 上次告警时间，suppress 用
        self.fixed_bucket: int = -1            # 固定窗口当前分片 floor(ts/seconds)


class DetectionEngine:
    """把事件喂进来，吐出触发的告警。"""

    def __init__(self) -> None:
        self._states: dict[tuple[str, str], WindowState] = {}

    def process(self, event: dict[str, Any], rules: list[Rule]) -> Iterator[Alert]:
        """处理单个事件。每条规则独立判断，命中且过阈值就 yield 一条告警。"""
        ts = event_timestamp(event)
        for rule in rules:
            if not match_rule(rule, event):
                continue
            key = extract_group_key(rule, event)
            state = self._state_for(rule.id, key)
            alert = self._update(rule, state, ts)
            if alert is not None:
                yield alert

    # ---- 内部 ----

    def _state_for(self, rule_id: str, group_value: str) -> WindowState:
        """获取或创建窗口状态。"""
        k = (rule_id, group_value)
        state = self._states.get(k)
        if state is None:
            state = WindowState(rule_id, group_value)
            self._states[k] = state
        return state

    def _update(self, rule: Rule, state: WindowState, ts: float) -> Optional[Alert]:
        """更新窗口状态，命中阈值时返回告警。"""
        w = rule.window
        seconds = w.seconds
        threshold = w.threshold

        if w.sliding:
            # —— 滑动窗口：弹出过期时间戳 ——
            cutoff = ts - seconds
            while state.hits and state.hits[0] < cutoff:
                state.hits.popleft()
            state.hits.append(ts)
            count = len(state.hits)
        else:
            # —— 固定窗口：按 floor(ts / seconds) 分片 ——
            bucket = int(ts // seconds)
            if bucket != state.fixed_bucket:
                # 跨分片：清空重计
                state.hits.clear()
                state.fixed_bucket = bucket
            state.hits.append(ts)
            count = len(state.hits)

        # 未达阈值
        if count < threshold:
            return None

        # 抑制：同一 group_value 在 suppress.seconds 内只报一次
        suppress_seconds = rule.suppress.seconds
        if suppress_seconds > 0 and (ts - state.last_alert_ts) < suppress_seconds:
            return None

        state.last_alert_ts = ts
        return Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            attack=rule.attack,
            group_value=state.group_value,
            count=count,
            window_seconds=seconds,
            description=rule.description,
            ts=_iso_ts(ts),
        )

    # ---- 维护 ----

    def prune(self, now: float | None = None) -> int:
        """清理长时间未命中的窗口状态，返回清理数量。

        用于长期运行时释放内存；滑动窗口状态若左端时间戳过于陈旧则移除。
        """
        if now is None:
            now = time.time()
        removed = 0
        stale: list[tuple[str, str]] = []
        for k, state in self._states.items():
            if not state.hits:
                stale.append(k)
            else:
                # 若最近一次命中已超过 1 小时，视为陈旧
                if now - state.hits[-1] > 3600:
                    stale.append(k)
        for k in stale:
            del self._states[k]
            removed += 1
        return removed

    def __len__(self) -> int:
        """当前维护的窗口状态数量。"""
        return len(self._states)
