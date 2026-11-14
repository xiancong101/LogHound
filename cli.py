"""LogHawk 命令行入口。

子命令：
    parse <logfile...>                只解析打印（调试）
    run   <logfile...> --rules rules/ 全量检测，输出告警
    tail  <logfile>   --rules rules/  类似 tail -f 的实时检测
    rules list                        列出已加载规则
    eval                              跑 baseline 对比评估
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from config import Config, load_config

from loghawk.output import (
    ConsoleOutput,
    MetricsOutput,
    StoreOutput,
    WebhookOutput,
    alert_from_rule,
)
from loghawk.parser import ParseStats, iter_events
from loghawk.rules import DetectionEngine, RuleLoader, RuleSet


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="loghawk",
        description="日志异常检测与告警引擎",
    )
    parser.add_argument("--config", default="config.yaml", help="配置文件路径（默认 config.yaml）")

    sub = parser.add_subparsers(dest="command", required=True)

    # parse
    p_parse = sub.add_parser("parse", help="只解析日志并打印（调试用）")
    p_parse.add_argument("logfiles", nargs="+", help="日志文件（支持 .log 和 .log.gz）")

    # run
    p_run = sub.add_parser("run", help="全量检测日志并输出告警")
    p_run.add_argument("logfiles", nargs="+", help="日志文件（支持 .log 和 .log.gz）")
    p_run.add_argument("--rules", default=None, help="规则目录（默认取配置 rules_dir）")
    p_run.add_argument("--no-db", action="store_true", help="不落库到 SQLite")

    # tail
    p_tail = sub.add_parser("tail", help="实时跟踪日志文件检测（类似 tail -f）")
    p_tail.add_argument("logfile", help="日志文件路径")
    p_tail.add_argument("--rules", default=None, help="规则目录（默认取配置 rules_dir）")
    p_tail.add_argument("--interval", type=float, default=1.0, help="轮询间隔（秒，默认 1.0）")

    # rules
    p_rules = sub.add_parser("rules", help="规则管理")
    p_rules_sub = p_rules.add_subparsers(dest="rules_command", required=True)
    p_rules_sub.add_parser("list", help="列出已加载规则")

    # eval
    sub.add_parser("eval", help="运行 baseline 对比评估")

    return parser


# ---- 公共工具 ----

def _load_ruleset(config: Config, rules_arg: str | None) -> RuleSet:
    """加载规则集（支持热加载）。"""
    rules_dir = Path(rules_arg) if rules_arg else config.rules_dir_path
    loader = RuleLoader()
    return RuleSet(loader, rules_dir, watch=True)


def _build_outputs(config: Config):
    """根据配置构建输出后端列表。"""
    outputs = []
    if config.output.console:
        outputs.append(ConsoleOutput())
    if config.output.webhook and config.webhook_url:
        outputs.append(WebhookOutput(config.webhook_url))
    outputs.append(StoreOutput(config.db_path_obj))  # 默认落库
    metrics = MetricsOutput()
    return outputs, metrics


def _dispatch(outputs, metrics, alert) -> None:
    """把一条告警分发到所有输出后端。"""
    unified = alert_from_rule(alert)
    for backend in outputs:
        backend.send(unified)
    metrics.send(unified)


def _close_outputs(outputs) -> None:
    for b in outputs:
        b.close()


# ---- 子命令实现 ----

def cmd_parse(args, config: Config) -> int:
    """parse：只解析打印，调试用。"""
    stats = ParseStats()
    for event in iter_events(args.logfiles, stats=stats):
        print(event)
    print(f"\n解析统计: {stats}", file=sys.stderr)
    return 0


def cmd_run(args, config: Config) -> int:
    """run：全量检测并输出告警。"""
    rs = _load_ruleset(config, args.rules)
    engine = DetectionEngine()
    outputs, metrics = _build_outputs(config)

    print(f"加载规则 {len(rs)} 条，开始检测...", file=sys.stderr)
    try:
        for event in iter_events(args.logfiles):
            rs.reload_if_changed()
            for alert in engine.process(event, rs.rules):
                _dispatch(outputs, metrics, alert)
    finally:
        _close_outputs(outputs)

    return 0


def cmd_tail(args, config: Config) -> int:
    """tail：类似 tail -f 的实时检测。"""
    rs = _load_ruleset(config, args.rules)
    engine = DetectionEngine()
    outputs, metrics = _build_outputs(config)

    path = Path(args.logfile)
    print(f"跟踪 {path}（规则 {len(rs)} 条，Ctrl+C 退出）...", file=sys.stderr)

    # 记录初始文件大小，从末尾开始 tail
    offset = path.stat().st_size if path.exists() else 0
    try:
        while True:
            rs.reload_if_changed()
            if path.exists():
                size = path.stat().st_size
                if size < offset:
                    # 文件被截断/轮转：从头开始
                    offset = 0
                if size > offset:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(offset)
                        for line in f:
                            # 直接复用 parser 单行解析
                            event = _parse_single(line)
                            if event is None:
                                continue
                            for alert in engine.process(event, rs.rules):
                                _dispatch(outputs, metrics, alert)
                    offset = size
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n已退出。", file=sys.stderr)
    finally:
        _close_outputs(outputs)

    return 0


def _parse_single(line: str):
    """解析单行日志（复用 parser 的 sniff + 对应解析器）。"""
    from loghawk.parser import parse_app, parse_nginx, parse_ssh, sniff_type

    log_type = sniff_type(line)
    if log_type == "nginx":
        return parse_nginx(line)
    if log_type == "ssh":
        return parse_ssh(line)
    if log_type == "app":
        return parse_app(line)
    return None


def cmd_rules_list(args, config: Config) -> int:
    """rules list：列出已加载规则。"""
    rs = _load_ruleset(config, None)
    print(f"共 {len(rs)} 条规则：\n")
    for r in rs.rules:
        attack = r.attack or "-"
        print(
            f"  {r.id:<28} [{r.severity:<6}] attack={attack:<12} "
            f"window={r.window.seconds}s/{r.window.threshold}次 group_by={r.window.group_by}"
        )
    return 0


def cmd_eval(args, config: Config) -> int:
    """eval：跑 baseline 对比评估。"""
    # 复用 scripts/offline_eval 的逻辑
    sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
    from offline_eval import build_baselines, load_points, to_eval_points

    from loghawk.baseline import format_report, run_evaluation

    data_dir = Path("data")
    normal_path = data_dir / "normal_logs.jsonl"
    attack_path = data_dir / "attack_logs.jsonl"

    if not normal_path.exists() or not attack_path.exists():
        print(
            "未找到评估数据，请先运行：\n"
            "  python scripts/make_fake_logs.py --days 30 --seed 42 --out-dir data",
            file=sys.stderr,
        )
        return 1

    normal = load_points(normal_path)
    attack = load_points(attack_path)
    baselines = build_baselines(normal)
    points = to_eval_points(attack)

    report = run_evaluation(points, baselines, fixed_threshold=200.0)
    print(format_report(report))
    return 0


# ---- 主入口 ----

def main(argv: list[str] | None = None) -> int:
    """命令行主入口，返回进程退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)

    handlers = {
        "parse": cmd_parse,
        "run": cmd_run,
        "tail": cmd_tail,
        "eval": cmd_eval,
    }
    if args.command == "rules":
        if args.rules_command == "list":
            return cmd_rules_list(args, config)
        return 1

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args, config)


if __name__ == "__main__":
    sys.exit(main())
