"""规则引擎模块的单元测试。

覆盖：
1. 规则加载 + schema 校验（非法字段报错含路径/字段/原因）
2. 滑动窗口触发告警
3. 固定窗口模式
4. 热加载（mtime 变化后重载）
5. 告警抑制（suppress）
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from loghound.rules import (
    DetectionEngine,
    RuleLoader,
    RuleLoadError,
    RuleSet,
    match_rule,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _ssh_event(ip: str = "10.0.0.5", ts: str = "2025-03-12T10:23:45") -> dict:
    """构造一条 SSH 登录失败事件。"""
    return {
        "ts": ts,
        "ip": ip,
        "method": None,
        "path": None,
        "status": None,
        "size": None,
        "ua": None,
        "raw": "",
        "log_type": "ssh",
    }


def test_load_all_rules() -> None:
    """20 条内置规则全部加载成功且 schema 校验通过。"""
    loader = RuleLoader()
    rs = RuleSet(loader, RULES_DIR)
    assert len(rs) == 20
    # 所有规则 id 唯一
    ids = [r.id for r in rs.rules]
    assert len(ids) == len(set(ids))


def test_schema_validation_reports_details(tmp_path: Path) -> None:
    """schema 校验对非法字段给出路径+字段+原因。"""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "id: x\nname: x\nseverity: critical\n"
        "match:\n  log_type: unknown\n  status: not_a_list\n"
        "window:\n  seconds: 0\n  threshold: 1\n  group_by: bogus\n",
        encoding="utf-8",
    )
    loader = RuleLoader()
    with pytest.raises(RuleLoadError) as exc_info:
        loader.load(bad)
    text = str(exc_info.value)
    assert "severity" in text
    assert "match.log_type" in text
    assert "match.status" in text
    assert "window.seconds" in text
    assert "window.group_by" in text


def test_sliding_window_triggers_alert() -> None:
    """滑动窗口达到阈值触发告警。"""
    loader = RuleLoader()
    rs = RuleSet(loader, RULES_DIR)
    engine = DetectionEngine()
    alerts = []
    for _ in range(10):
        for a in engine.process(_ssh_event(), rs.rules):
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "bruteforce_ssh"
    assert alerts[0].group_value == "10.0.0.5"
    assert alerts[0].count == 10


def test_fixed_window_resets_on_new_bucket() -> None:
    """固定窗口模式：跨分片清空重计，不累计到告警。"""
    # 构造一个固定窗口规则：60 秒窗口、阈值 3
    from loghound.rules.models import Match, Rule, Suppress, Window

    rule = Rule(
        id="fixed_test",
        name="固定窗口测试",
        severity="medium",
        match=Match(log_type="ssh"),
        window=Window(seconds=60, threshold=3, group_by="ip", sliding=False),
        suppress=Suppress(seconds=0),
    )
    engine = DetectionEngine()
    alerts = []
    # 前 2 次在第一个 60s 分片内
    for ts in ("2025-03-12T10:00:00", "2025-03-12T10:00:10"):
        for a in engine.process(_ssh_event(ts=ts), [rule]):
            alerts.append(a)
    assert len(alerts) == 0
    # 第 3 次跨到下一个分片，计数应重置为 1，仍不告警
    for a in engine.process(_ssh_event(ts="2025-03-12T10:01:05"), [rule]):
        alerts.append(a)
    assert len(alerts) == 0


def test_hot_reload_on_mtime_change(tmp_path: Path) -> None:
    """热加载：规则目录 mtime 变化后重载新规则。"""
    loader = RuleLoader()
    # 初始只有 1 条规则
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yaml").write_text(
        "id: a\nname: a\nseverity: low\nmatch: {}\nwindow: {}\n", encoding="utf-8"
    )
    rs = RuleSet(loader, rules_dir, watch=True)
    assert len(rs) == 1

    # 新增一条规则
    (rules_dir / "b.yaml").write_text(
        "id: b\nname: b\nseverity: low\nmatch: {}\nwindow: {}\n", encoding="utf-8"
    )
    # mtime 精度问题：确保时间戳确实变化
    time.sleep(0.01)
    changed = rs.reload_if_changed()
    assert changed is True
    assert len(rs) == 2


def test_suppress_limits_duplicate_alerts() -> None:
    """告警抑制：同一 group_value 在 suppress 秒内只报一次。"""
    from loghound.rules.models import Match, Rule, Suppress, Window

    rule = Rule(
        id="suppress_test",
        name="抑制测试",
        severity="high",
        match=Match(log_type="ssh"),
        window=Window(seconds=60, threshold=2, group_by="ip", sliding=True),
        suppress=Suppress(seconds=600),
    )
    engine = DetectionEngine()
    alerts = []
    # 第 2 次达到阈值，触发告警
    for ts in ("2025-03-12T10:00:00", "2025-03-12T10:00:10"):
        for a in engine.process(_ssh_event(ts=ts), [rule]):
            alerts.append(a)
    assert len(alerts) == 1
    # 继续命中，但因抑制不再告警
    for a in engine.process(_ssh_event(ts="2025-03-12T10:00:20"), [rule]):
        alerts.append(a)
    assert len(alerts) == 1
