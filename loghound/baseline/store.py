"""SQLite 基线存储：基线表的读写与滑动平均更新。

表结构：:

    baseline(ip TEXT, hour INT, mean REAL, std REAL, sample_count INT, updated_at TEXT,
             PRIMARY KEY(ip, hour))

更新策略：滑动平均。新批次数据权重为 ``ALPHA``（默认 0.3）：

    mean_new = alpha * batch_mean + (1 - alpha) * mean_old
    std_new  = alpha * batch_std  + (1 - alpha) * std_old

样本量 ``sample_count`` 单调累计，用于判断基线是否已“成熟”。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

# 滑动平均中，新批次数据的权重
ALPHA = 0.3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    ip           TEXT NOT NULL,
    hour         INTEGER NOT NULL,
    mean         REAL NOT NULL,
    std          REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (ip, hour)
);
"""


class BaselineStore:
    """基于 SQLite 的基线存储与更新。"""

    def __init__(self, db_path: Path | str) -> None:
        """打开（或创建）指定路径的 SQLite 数据库并建表。"""
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    # ---- 查询 ----

    def get(self, ip: str, hour: int) -> Optional[dict]:
        """获取某个 (ip, hour) 的基线记录，不存在返回 None。"""
        row = self._conn.execute(
            "SELECT ip, hour, mean, std, sample_count, updated_at "
            "FROM baseline WHERE ip = ? AND hour = ?",
            (ip, hour),
        ).fetchone()
        if row is None:
            return None
        return {
            "ip": row["ip"],
            "hour": row["hour"],
            "mean": row["mean"],
            "std": row["std"],
            "sample_count": row["sample_count"],
            "updated_at": row["updated_at"],
        }

    def get_all(self) -> list[dict]:
        """返回全部基线记录。"""
        rows = self._conn.execute(
            "SELECT ip, hour, mean, std, sample_count, updated_at FROM baseline"
        ).fetchall()
        return [
            {
                "ip": r["ip"],
                "hour": r["hour"],
                "mean": r["mean"],
                "std": r["std"],
                "sample_count": r["sample_count"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    # ---- 更新 ----

    def update(self, ip: str, hour: int, batch_mean: float, batch_std: float, batch_count: int) -> dict:
        """用新批次统计量滑动平均更新基线，返回更新后的记录。

        参数：
            ip: 来源 IP。
            hour: 小时（0-23）。
            batch_mean: 本批次请求量的均值。
            batch_std: 本批次请求量的标准差。
            batch_count: 本批次样本数。
        """
        existing = self.get(ip, hour)
        now = datetime.now().isoformat(timespec="seconds")

        if existing is None:
            # 首次：直接采用新批次统计量
            mean = float(batch_mean)
            std = float(batch_std)
            sample_count = int(batch_count)
        else:
            # 滑动平均
            mean = ALPHA * float(batch_mean) + (1 - ALPHA) * existing["mean"]
            std = ALPHA * float(batch_std) + (1 - ALPHA) * existing["std"]
            sample_count = existing["sample_count"] + int(batch_count)

        self._conn.execute(
            "INSERT INTO baseline (ip, hour, mean, std, sample_count, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, hour) DO UPDATE SET "
            "mean = excluded.mean, std = excluded.std, "
            "sample_count = excluded.sample_count, updated_at = excluded.updated_at",
            (ip, hour, mean, std, sample_count, now),
        )
        self._conn.commit()
        return {
            "ip": ip,
            "hour": hour,
            "mean": mean,
            "std": std,
            "sample_count": sample_count,
            "updated_at": now,
        }

    def upsert(self, ip: str, hour: int, mean: float, std: float, sample_count: int) -> None:
        """直接写入（覆盖）一条基线记录，用于离线批量灌入历史基线。"""
        now = datetime.now().isoformat(timespec="seconds")
        self._conn.execute(
            "INSERT INTO baseline (ip, hour, mean, std, sample_count, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, hour) DO UPDATE SET "
            "mean = excluded.mean, std = excluded.std, "
            "sample_count = excluded.sample_count, updated_at = excluded.updated_at",
            (ip, hour, float(mean), float(std), int(sample_count), now),
        )
        self._conn.commit()

    # ---- 维护 ----

    def close(self) -> None:
        """关闭数据库连接。"""
        self._conn.close()

    def __enter__(self) -> "BaselineStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
