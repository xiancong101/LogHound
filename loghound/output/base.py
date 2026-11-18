"""告警输出抽象基类与统一的 Alert 数据结构。

output 模块消费两种来源的告警：
- 规则引擎（``loghound.rules``）产出的告警，含 rule_id / severity / attack / count。
- 基线引擎（``loghound.baseline``）产出的异常，含 ip / z / burst_ratio。

:class:`Alert` 是两者的统一中间结构，各输出后端（console / webhook /
store / metrics）只需消费这一种类型。
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

# 严重级别到颜色的映射（供 console 输出使用，各后端可复用）
SEVERITY_COLORS: dict[str, str] = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}


@dataclass
class Alert:
    """一条统一的告警记录。"""

    severity: str
    rule_id: str
    group_value: str = ""          # 聚合键（通常为 IP）
    count: int = 0                 # 命中次数
    attack: Optional[str] = None   # ATT&CK 编号
    ts: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    detail: dict[str, Any] = field(default_factory=dict)  # 额外信息（z/burst 等）

    def as_dict(self) -> dict[str, Any]:
        """转为可序列化 dict。"""
        return {
            "ts": self.ts,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "group_value": self.group_value,
            "count": self.count,
            "attack": self.attack,
            "detail": self.detail,
        }

    def to_json(self) -> str:
        """序列化为 JSON 字符串（供 webhook / 落库使用）。"""
        return json.dumps(self.as_dict(), ensure_ascii=False)


class OutputBackend(ABC):
    """告警输出后端抽象基类。"""

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """发送一条告警。"""

    def close(self) -> None:
        """可选的后端清理（子类按需覆盖）。"""


def alert_from_rule(a) -> Alert:
    """从规则引擎的 ``rules.models.Alert`` 构造统一 :class:`Alert`。"""
    return Alert(
        severity=a.severity,
        rule_id=a.rule_id,
        group_value=a.group_value,
        count=a.count,
        attack=a.attack,
        ts=a.ts or datetime.now().isoformat(timespec="seconds"),
        detail={"rule_name": a.rule_name, "description": a.description,
                "window_seconds": a.window_seconds},
    )


def alert_from_baseline(s) -> Alert:
    """从基线引擎的 ``baseline.ScoreResult`` 构造统一 :class:`Alert`。"""
    return Alert(
        severity="medium" if s.is_anomaly else "low",
        rule_id=f"baseline_anomaly_{s.hour}",
        group_value=s.ip,
        count=int(s.current),
        attack=None,
        detail={
            "hour": s.hour,
            "mean": s.mean,
            "std": s.std,
            "z": s.z,
            "burst_ratio": s.burst_ratio,
            "score": s.score,
        },
    )
