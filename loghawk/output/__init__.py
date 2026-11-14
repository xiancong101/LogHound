"""告警输出模块：将告警发送到不同渠道。

对外暴露：
- :class:`Alert` / :class:`OutputBackend`：统一告警结构与抽象基类
- :class:`ConsoleOutput`：控制台带颜色输出
- :class:`WebhookOutput`：Webhook POST（指数退避重试）
- :class:`StoreOutput`：SQLite 落库
- :class:`MetricsOutput`：Prometheus 指标
- :func:`alert_from_rule` / :func:`alert_from_baseline`：来源告警转换
"""

from .base import (
    Alert,
    OutputBackend,
    SEVERITY_COLORS,
    alert_from_baseline,
    alert_from_rule,
)
from .console import ConsoleOutput
from .metrics import MetricsOutput, make_app, serve
from .store import StoreOutput
from .webhook import WebhookOutput

__all__ = [
    "Alert",
    "OutputBackend",
    "SEVERITY_COLORS",
    "alert_from_rule",
    "alert_from_baseline",
    "ConsoleOutput",
    "WebhookOutput",
    "StoreOutput",
    "MetricsOutput",
    "make_app",
    "serve",
]
