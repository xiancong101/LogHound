"""Prometheus 指标输出：提供 /metrics 端点（可选 Flask），输出文本格式。

导出两类指标：
- ``loghawk_alerts_total{severity, rule_id}``：累计告警数（计数器）。
- ``loghawk_alerts_last_count{rule_id, group_value}``：最近一次告警的命中数。

不依赖 Flask：核心是 :func:`render_metrics` 生成 Prometheus 文本；
Flask 只在需要 HTTP 端点时使用（``serve``）。
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from .base import Alert, OutputBackend

# Prometheus 指标名（合法：字母数字 + 下划线）
METRIC_ALERTS_TOTAL = "loghawk_alerts_total"
METRIC_ALERTS_LAST_COUNT = "loghawk_alerts_last_count"


def _escape_label(value: str) -> str:
    """转义 Prometheus label 值中的反斜杠与双引号。"""
    return value.replace("\\", "\\\\").replace('"', '\\"')


class MetricsOutput(OutputBackend):
    """把告警累积为 Prometheus 指标，供 /metrics 抓取。"""

    def __init__(self) -> None:
        # (severity, rule_id) -> 计数
        self._alerts_total: dict[tuple[str, str], int] = {}
        # rule_id -> (group_value, count)
        self._last: dict[str, tuple[str, int]] = {}
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> None:
        """累计一条告警。"""
        with self._lock:
            key = (alert.severity, alert.rule_id)
            self._alerts_total[key] = self._alerts_total.get(key, 0) + 1
            self._last[alert.rule_id] = (alert.group_value, alert.count)

    def render_metrics(self) -> str:
        """生成 Prometheus 文本格式的指标内容。"""
        with self._lock:
            lines: list[str] = []

            # 计数器
            lines.append(f"# HELP {METRIC_ALERTS_TOTAL} 累计告警数（按严重级别与规则）。")
            lines.append(f"# TYPE {METRIC_ALERTS_TOTAL} counter")
            for (severity, rule_id), count in sorted(self._alerts_total.items()):
                labels = (
                    f'severity="{_escape_label(severity)}",'
                    f'rule_id="{_escape_label(rule_id)}"'
                )
                lines.append(f"{METRIC_ALERTS_TOTAL}{{{labels}}} {count}")

            # 最近命中数
            lines.append(f"# HELP {METRIC_ALERTS_LAST_COUNT} 最近一次告警的命中数。")
            lines.append(f"# TYPE {METRIC_ALERTS_LAST_COUNT} gauge")
            for rule_id, (group_value, count) in sorted(self._last.items()):
                labels = (
                    f'rule_id="{_escape_label(rule_id)}",'
                    f'group_value="{_escape_label(group_value)}"'
                )
                lines.append(f"{METRIC_ALERTS_LAST_COUNT}{{{labels}}} {count}")

            return "\n".join(lines) + "\n"


def make_app(metrics: MetricsOutput) -> Callable:
    """用 Flask 构建一个暴露 /metrics 端点的 WSGI 应用。

    仅在需要 HTTP 端点时调用（Flask 为可选依赖）。
    """
    try:
        from flask import Flask, Response
    except ImportError as exc:  # pragma: no cover - 依赖缺失提示
        raise RuntimeError("启用 /metrics 端点需要安装 Flask（pip install Flask）") from exc

    app = Flask(__name__)

    @app.route("/metrics")
    def metrics_endpoint():
        return Response(
            metrics.render_metrics(),
            mimetype="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.route("/health")
    def health():
        return "ok"

    return app


def serve(metrics: MetricsOutput, host: str = "0.0.0.0", port: int = 9090, **kwargs) -> None:
    """启动 Flask 开发服务器暴露 /metrics（阻塞调用）。"""
    app = make_app(metrics)
    app.run(host=host, port=port, **kwargs)
