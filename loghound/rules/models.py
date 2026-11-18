"""规则引擎数据模型：规则、匹配结果与告警的 dataclass 定义。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

# 合法取值常量
SEVERITIES: tuple[str, ...] = ("high", "medium", "low")
GROUP_BY_CHOICES: tuple[str, ...] = ("ip", "ip+path", "ua", "path", "none")


@dataclass
class Match:
    """单条日志的门槛匹配条件（全部满足才进入窗口统计）。"""

    log_type: Optional[str] = None
    status: Optional[list[int]] = None
    path_regex: Optional[str] = None
    ua_regex: Optional[str] = None
    method: Optional[list[str]] = None
    min_size: Optional[int] = None

    def is_empty(self) -> bool:
        """门槛条件是否为空（空表示匹配所有事件）。"""
        return (
            self.log_type is None
            and self.status is None
            and self.path_regex is None
            and self.ua_regex is None
            and self.method is None
            and self.min_size is None
        )


@dataclass
class Window:
    """时间窗与阈值配置。"""

    seconds: int = 300
    threshold: int = 10
    group_by: str = "ip"
    sliding: bool = True


@dataclass
class Suppress:
    """告警抑制配置：同一 group_by 值在指定秒内只报一次。"""

    seconds: int = 600


@dataclass
class Rule:
    """一条检测规则（对应一个 YAML 文件）。"""

    id: str
    name: str
    severity: str
    description: str = ""
    attack: Optional[str] = None
    match: Match = field(default_factory=Match)
    window: Window = field(default_factory=Window)
    suppress: Suppress = field(default_factory=Suppress)
    source: str = ""  # 规则来源文件路径（用于报错定位）

    # 运行时预编译的字段（由 loader 填充，避免每次匹配都重新编译正则）
    compiled_path: Any = field(default=None, repr=False)
    compiled_ua: Any = field(default=None, repr=False)


@dataclass
class Alert:
    """一次窗口命中后产生的告警。"""

    rule_id: str
    rule_name: str
    severity: str
    attack: Optional[str]
    group_value: str
    count: int
    window_seconds: int
    description: str = ""
    ts: str = ""  # 告警触发时间（ISO8601，由检测引擎填入）

    def as_dict(self) -> dict[str, Any]:
        """转为可序列化 dict（供输出模块使用）。"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "attack": self.attack,
            "group_value": self.group_value,
            "count": self.count,
            "window_seconds": self.window_seconds,
            "description": self.description,
            "ts": self.ts,
        }
