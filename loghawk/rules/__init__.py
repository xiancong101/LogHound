"""规则引擎模块：YAML 规则加载、schema 校验、匹配与窗口检测。

对外暴露：
- :class:`RuleLoader`：规则加载器
- :class:`RuleSet`：支持热加载的规则集合容器
- :class:`DetectionEngine`：窗口状态管理与检测引擎
- :class:`Rule` / :class:`Alert` 等数据模型
- :func:`match_rule` / :func:`extract_group_key`：匹配与聚合辅助
"""

from .loader import RuleLoader, RuleLoadError, RuleSet
from .matcher import event_timestamp, extract_group_key, match_rule
from .models import Alert, Match, Rule, Suppress, Window
from .schema import SchemaError, validate_rule
from .window import DetectionEngine, WindowState

__all__ = [
    "RuleLoader",
    "RuleLoadError",
    "RuleSet",
    "DetectionEngine",
    "WindowState",
    "Rule",
    "Alert",
    "Match",
    "Window",
    "Suppress",
    "SchemaError",
    "validate_rule",
    "match_rule",
    "extract_group_key",
    "event_timestamp",
]
