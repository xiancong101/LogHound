"""baseline 模块的单元测试。

覆盖：
1. 滑动平均更新（新批次权重 0.3）
2. z-score 计算（std=0 视为 1）
3. 突增比计算（prev=0 边界）
4. 综合打分与 is_anomaly 判定
5. 离线评估：固定阈值 vs 基线+3σ
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from loghound.baseline import (
    Baseline,
    BaselineStore,
    EvalPoint,
    evaluate_baseline_3sigma,
    evaluate_fixed_threshold,
    score,
    compute_spike_ratio,
    compute_zscore,
)


def test_sliding_average_update() -> None:
    """滑动平均更新：新批次权重 0.3。"""
    with tempfile.TemporaryDirectory() as tmp:
        store = BaselineStore(Path(tmp) / "test.db")
        # 首次写入：直接采用新值
        rec = store.update("1.2.3.4", 12, batch_mean=100.0, batch_std=20.0, batch_count=10)
        assert rec["mean"] == 100.0
        assert rec["std"] == 20.0
        assert rec["sample_count"] == 10

        # 第二次：mean = 0.3*200 + 0.7*100 = 130
        rec2 = store.update("1.2.3.4", 12, batch_mean=200.0, batch_std=40.0, batch_count=10)
        assert abs(rec2["mean"] - 130.0) < 1e-9
        assert abs(rec2["std"] - (0.3 * 40 + 0.7 * 20)) < 1e-9
        assert rec2["sample_count"] == 20
        store.close()


def test_zscore_zero_std() -> None:
    """std=0 时 z 计算用 1 代替，避免除零。"""
    assert compute_zscore(105.0, 100.0, 0.0) == 5.0  # (105-100)/1
    assert compute_zscore(100.0, 100.0, 0.0) == 0.0
    assert compute_zscore(110.0, 100.0, 5.0) == 2.0


def test_spike_ratio() -> None:
    """突增比：recent/prev，prev=0 的边界。"""
    assert compute_spike_ratio(90.0, 30.0) == 3.0
    assert compute_spike_ratio(0.0, 30.0) == 0.0
    # prev=0 且 recent>0 视为强突增
    assert compute_spike_ratio(50.0, 0.0) == 50.0
    assert compute_spike_ratio(0.0, 0.0) == 0.0


def test_score_is_anomaly() -> None:
    """综合打分：z>3 或 burst>3 判定异常。"""
    # 正常：z 小、burst 小
    normal = score(ip="1.2.3.4", hour=12, current=110.0, mean=100.0, std=20.0,
                   recent=30.0, prev=28.0)
    assert normal.is_anomaly is False

    # z 超阈值
    z_anom = score(ip="1.2.3.4", hour=12, current=200.0, mean=100.0, std=20.0,
                   recent=30.0, prev=28.0)
    assert z_anom.is_anomaly is True
    assert z_anom.z == 5.0

    # burst 超阈值（即便 z 不超）
    burst_anom = score(ip="1.2.3.4", hour=12, current=110.0, mean=100.0, std=20.0,
                       recent=100.0, prev=10.0)
    assert burst_anom.is_anomaly is True
    assert burst_anom.burst_ratio == 10.0


def test_offline_evaluation_contrast() -> None:
    """离线评估：基线+3σ 比固定阈值误报更少。"""
    # 构造：正常业务有高峰（current 大但非攻击），攻击点 current 也大
    points = [
        # 业务高峰（非攻击）：固定阈值会误报
        EvalPoint(ip="1.2.3.4", hour=18, current=250.0, recent=60.0, prev=55.0, is_attack=False),
        EvalPoint(ip="1.2.3.4", hour=19, current=260.0, recent=62.0, prev=60.0, is_attack=False),
        # 真实攻击：current 远超基线
        EvalPoint(ip="1.2.3.4", hour=3, current=500.0, recent=120.0, prev=15.0, is_attack=True),
        # 正常低谷
        EvalPoint(ip="1.2.3.4", hour=4, current=20.0, recent=5.0, prev=5.0, is_attack=False),
    ]
    # 基线：hour=3 均值 30，hour=18/19 均值 240（业务高峰），hour=4 均值 25
    baselines = {
        ("1.2.3.4", 18): Baseline(mean=240.0, std=20.0),
        ("1.2.3.4", 19): Baseline(mean=240.0, std=20.0),
        ("1.2.3.4", 3): Baseline(mean=30.0, std=10.0),
        ("1.2.3.4", 4): Baseline(mean=25.0, std=5.0),
    }

    fixed = evaluate_fixed_threshold(points, threshold=200.0)
    base = evaluate_baseline_3sigma(points, baselines)

    # 固定阈值：250、260、500 都 > 200，其中前两个是误报
    assert fixed.alerts == 3
    assert fixed.false_positives == 2
    assert fixed.false_negatives == 0

    # 基线+3σ：250/260 在各自基线内不异常，500 是异常
    assert base.alerts == 1
    assert base.false_positives == 0
    assert base.false_negatives == 0
    assert base.true_positives == 1
