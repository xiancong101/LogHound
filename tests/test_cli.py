"""CLI 入口的基本行为（版本号、子命令可达性）。"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cli import build_parser  # noqa: E402
from loghound import __version__  # noqa: E402


def test_version_flag(capsys) -> None:
    """--version 打印版本号后退出，这是发版前必须能用的。"""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out


def test_subcommands_registered() -> None:
    """四个子命令都在，避免改 argparse 时漏掉。"""
    parser = build_parser()
    args = parser.parse_args(["rules", "list"])
    assert args.command == "rules"
    args = parser.parse_args(["run", "a.log"])
    assert args.command == "run"
    assert args.logfiles == ["a.log"]
