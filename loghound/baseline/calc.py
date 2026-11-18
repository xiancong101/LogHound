"""基线打分：z-score 配合短时突增比。

单独看 z-score 会把业务波峰全判成异常，所以再叠一个 burst_ratio
（近 5 分钟量 / 前 5 分钟量）做交叉验证，两个都超才算异常。
std 为 0 时按 STD_FALLBACK 处理，不然会除零。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# 默认阈值
DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_BURST_THRESHOLD = 3.0
# 默认权重
DEFAULT_W_Z = 0.6
DEFAULT_W_BURST = 0.4
# std 为 0 时的替代值（避免除零，同时让 z 不至于无穷大）
STD_FALLBACK = 1.0


@dataclass
class ScoreResult:
    """一次打分的完整结果。"""

    ip: str
    hour: int
    current: float
    mean: float
    std: float
    z: float
    burst_ratio: float
    score: float
    is_anomaly: bool

    def as_dict(self) -> dict:
        """转为可序列化 dict（与需求文档字段一一对应）。"""
        return {
            "ip": self.ip,
            "hour": self.hour,
            "current": self.current,
            "mean": self.mean,
            "std": self.std,
            "z": self.z,
            "burst_ratio": self.burst_ratio,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
        }


def compute_zscore(current: float, mean: float, std: float) -> float:
    """计算 z-score；std 为 0 或缺失时用 STD_FALLBACK 代替。"""
    if std is None:
        std = STD_FALLBACK
    if std == 0.0:
        std = STD_FALLBACK
    return (current - mean) / std


def compute_spike_ratio(recent: float, prev: float) -> float:
    """计算短时突增比：最近 5 分钟量 / 前 5 分钟量。

    前一时段为 0 时：若当前有量则视为强突增（返回较大值），
    否则返回 0（无突增）。
    """
    if prev == 0.0:
        return float(recent) if recent > 0 else 0.0
    return recent / prev


def score(
    *,
    ip: str,
    hour: int,
    current: float,
    mean: float,
    std: float,
    recent: float,
    prev: float,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    burst_threshold: float = DEFAULT_BURST_THRESHOLD,
    w_z: float = DEFAULT_W_Z,
    w_burst: float = DEFAULT_W_BURST,
) -> ScoreResult:
    """对某 IP 当前小时的请求量做异常打分，返回 :class:`ScoreResult`。

    参数：
        ip: 来源 IP。
        hour: 当前小时（0-23）。
        current: 当前小时的请求量。
        mean / std: 该 (ip, hour) 的基线均值与标准差。
        recent: 最近 5 分钟的请求量。
        prev: 前 5 分钟的请求量。
        z_threshold / burst_threshold / w_z / w_burst: 阈值与权重（可配置）。
    """
    z = compute_zscore(current, mean, std)
    burst = compute_spike_ratio(recent, prev)
    combined = w_z * z + w_burst * burst
    is_anomaly = (z > z_threshold) or (burst > burst_threshold)

    return ScoreResult(
        ip=ip,
        hour=hour,
        current=current,
        mean=mean,
        std=std,
        z=z,
        burst_ratio=burst,
        score=combined,
        is_anomaly=is_anomaly,
    )
