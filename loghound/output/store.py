"""SQLite 告警落库：把告警写入 alerts 表。

表结构：:

    alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        rule_id TEXT,
        severity TEXT,
        group_value TEXT,
        count INTEGER,
        detail_json TEXT,
        attack TEXT
    )
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .base import Alert, OutputBackend

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    group_value TEXT,
    count       INTEGER,
    detail_json TEXT,
    attack      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


class StoreOutput(OutputBackend):
    """把告警落库到 SQLite alerts 表。"""

    def __init__(self, db_path: Path | str) -> None:
        """打开（或创建）数据库并建表。"""
        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def send(self, alert: Alert) -> None:
        """插入一条告警记录。"""
        self._conn.execute(
            "INSERT INTO alerts (ts, rule_id, severity, group_value, count, detail_json, attack) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                alert.ts,
                alert.rule_id,
                alert.severity,
                alert.group_value,
                alert.count,
                json.dumps(alert.detail, ensure_ascii=False),
                alert.attack,
            ),
        )
        self._conn.commit()

    def query_recent(self, limit: int = 100) -> list[dict]:
        """查询最近的告警记录（供调试或 UI 展示）。"""
        rows = self._conn.execute(
            "SELECT ts, rule_id, severity, group_value, count, detail_json, attack "
            "FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "ts": r[0],
                "rule_id": r[1],
                "severity": r[2],
                "group_value": r[3],
                "count": r[4],
                "detail": json.loads(r[5]) if r[5] else {},
                "attack": r[6],
            }
            for r in rows
        ]

    def close(self) -> None:
        """关闭数据库连接。"""
        self._conn.close()
