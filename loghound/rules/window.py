"""窗口状态管理与检测引擎。

核心是 :class:`WindowState` 与 :class:`DetectionEngine`：

- 每个 ``(rule_id, group_value)`` 维护一个 ``deque`` 存命中时间戳，
  超出窗口的左端弹出（滑动窗口），或按整点分片对齐（固定窗口）。
- 当窗口内命中次数达到阈值时触发告警，并按 ``suppress`` 做抑制。

窗口实现区分两种模式：
    - 滑动窗口（``sliding=true``）：每次命中后把小于 ``now - seconds`` 的时间戳
      从 deque 左端弹出，deque 长度即当前窗口内命中数。
    - 固定窗口（``sliding=false``）：把时间戳对齐到 ``floor(ts / seconds)`` 分片，
      只统计同一分片内的命中数，跨分片则清空重计。
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
    """单个 ``(rule_id, group_value)`` 的窗口命中状态。"""

    __slots__ = ("rule_id", "group_value", "hits", "last_alert_ts", "fixed_bucket")

    def __init__(self, rule_id: str, group_value: str) -> None:
        self.rule_id = rule_id
        self.group_value = group_value
        # 命中时间戳（Unix 秒），滑动窗口用；固定窗口只保留当前分片内
        self.hits: deque[float] = deque()
        # 上次告警时间，用于 suppress 抑制
        self.last_alert_ts: float = 0.0
        # 固定窗口：当前所在分片编号（floor(ts / seconds)）
        self.fixed_bucket: int = -1


class DetectionEngine:
    """规则检测引擎：维护窗口状态，喂入事件并产出告警。

    用法::

        engine = DetectionEngine()
        for event in stream:
            for alert in engine.process(event):
                print(alert.as_dict())
    """

    def __init__(self) -> None:
        # 键为 (rule_id, group_value)，值为 WindowState
        self._states: dict[tuple[str, str], WindowState] = {}

    def process(self, event: dict[str, Any], rules: list[Rule]) -> Iterator[Alert]:
        """处理单个事件，返回由此触发的告警列表（生成器）。

        对每条规则：先做门槛匹配，再提取聚合键，更新对应窗口状态，
        达到阈值且未被抑制时产出一条告警。
        """
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
