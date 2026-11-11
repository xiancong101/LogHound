"""统计基线模块：按 (ip, hour) 建立请求量基线并做异常打分。

对外暴露：
- :class:`BaselineStore`：SQLite 基线存储与滑动平均更新
- :func:`score` / :func:`compute_z` / :func:`compute_burst_ratio`：异常打分
- :class:`ScoreResult`：打分结果
- :func:`run_evaluation` / :func:`format_report`：离线评估对比
"""

from .calc import (
    DEFAULT_BURST_THRESHOLD,
    DEFAULT_W_BURST,
    DEFAULT_W_Z,
    DEFAULT_Z_THRESHOLD,
    ScoreResult,
    compute_burst_ratio,
    compute_z,
    score,
)
from .evaluator import (
    Baseline,
    EvalPoint,
    EvalReport,
    StrategyResult,
    evaluate_baseline_3sigma,
    evaluate_fixed_threshold,
    format_report,
    run_evaluation,
)
from .store import ALPHA, BaselineStore

__all__ = [
    "BaselineStore",
    "ALPHA",
    "score",
    "compute_z",
    "compute_burst_ratio",
    "ScoreResult",
    "DEFAULT_Z_THRESHOLD",
    "DEFAULT_BURST_THRESHOLD",
    "DEFAULT_W_Z",
    "DEFAULT_W_BURST",
    "run_evaluation",
    "format_report",
    "evaluate_fixed_threshold",
    "evaluate_baseline_3sigma",
    "EvalPoint",
    "EvalReport",
    "StrategyResult",
    "Baseline",
]
