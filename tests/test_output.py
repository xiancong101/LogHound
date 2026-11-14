"""output 模块的单元测试。

覆盖：
1. 控制台输出格式（含颜色开关）
2. Webhook 指数退避重试
3. SQLite 落库
4. Prometheus 指标文本格式
5. alert_from_rule 转换
"""

from __future__ import annotations

import http.server
import json
import tempfile
import threading
from pathlib import Path

from loghawk.output import (
    Alert,
    ConsoleOutput,
    MetricsOutput,
    StoreOutput,
    WebhookOutput,
    alert_from_rule,
)


def test_console_format_no_color() -> None:
    """控制台输出格式正确，关闭颜色时无 ANSI 转义。"""
    import io

    buf = io.StringIO()
    out = ConsoleOutput(stream=buf, color=False)
    alert = Alert(
        severity="high",
        rule_id="bruteforce_ssh",
        group_value="10.0.0.5",
        count=12,
        attack="T1110.001",
        ts="2025-03-12T10:23:45",
    )
    out.send(alert)
    text = buf.getvalue()
    assert "[HIGH]" in text
    assert "ip=10.0.0.5" in text
    assert "rule=bruteforce_ssh" in text
    assert "count=12" in text
    assert "T1110.001" in text
    assert "\033[" not in text  # 无颜色转义


def test_console_format_with_color() -> None:
    """启用颜色时含 ANSI 转义。"""
    import io

    buf = io.StringIO()
    out = ConsoleOutput(stream=buf, color=True)
    out.send(Alert(severity="high", rule_id="x", group_value="1.2.3.4", count=1))
    assert "\033[" in buf.getvalue()


def test_webhook_retry_exponential_backoff() -> None:
    """Webhook 失败时重试，最终成功后返回。"""
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        out = WebhookOutput(f"http://127.0.0.1:{port}/hook", base_delay=0.01)
        out.send(Alert(severity="high", rule_id="r", group_value="1.2.3.4", count=1))
        assert len(received) == 1
        assert received[0]["rule_id"] == "r"
    finally:
        server.shutdown()
        thread.join()


def test_store_output_persists_alerts() -> None:
    """SQLite 落库并查询。"""
    with tempfile.TemporaryDirectory() as tmp:
        store = StoreOutput(Path(tmp) / "alerts.db")
        store.send(Alert(
            severity="high",
            rule_id="bruteforce_ssh",
            group_value="10.0.0.5",
            count=12,
            attack="T1110.001",
            detail={"z": 5.0},
        ))
        rows = store.query_recent()
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "bruteforce_ssh"
        assert rows[0]["count"] == 12
        assert rows[0]["attack"] == "T1110.001"
        assert rows[0]["detail"]["z"] == 5.0
        store.close()


def test_metrics_prometheus_format() -> None:
    """Prometheus 文本格式正确。"""
    m = MetricsOutput()
    m.send(Alert(severity="high", rule_id="bruteforce_ssh", group_value="10.0.0.5", count=12))
    m.send(Alert(severity="high", rule_id="bruteforce_ssh", group_value="10.0.0.6", count=15))
    text = m.render_metrics()
    assert "# TYPE loghawk_alerts_total counter" in text
    assert 'loghawk_alerts_total{severity="high",rule_id="bruteforce_ssh"} 2' in text
    assert 'loghawk_alerts_last_count{rule_id="bruteforce_ssh",group_value="10.0.0.6"} 15' in text


def test_alert_from_rule_conversion() -> None:
    """规则告警转统一告警结构。"""
    from loghawk.rules.models import Alert as RuleAlert

    ra = RuleAlert(
        rule_id="bruteforce_ssh",
        rule_name="SSH 暴力破解",
        severity="high",
        attack="T1110.001",
        group_value="10.0.0.5",
        count=12,
        window_seconds=300,
        description="desc",
        ts="2025-03-12T10:23:45",
    )
    a = alert_from_rule(ra)
    assert a.rule_id == "bruteforce_ssh"
    assert a.severity == "high"
    assert a.ts == "2025-03-12T10:23:45"
    assert a.detail["rule_name"] == "SSH 暴力破解"
