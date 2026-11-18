"""日志解析模块的单元测试。

覆盖：
1. Nginx 日志解析（主通道）
2. SSH 日志解析（主通道）
3. 应用 JSON 日志解析（主通道）
4. 正则失配自动走备通道
5. gzip 文件流式读取
"""

from __future__ import annotations

import gzip
from pathlib import Path

from loghound.parser import (
    iter_events,
    parse_app,
    parse_nginx,
    parse_ssh,
    sniff_type,
)


def test_parse_nginx() -> None:
    """Nginx combined 格式通过主通道解析出完整字段。"""
    line = (
        '127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] '
        '"GET /admin.php HTTP/1.1" 404 162 "-" "sqlmap/1.7"'
    )
    event = parse_nginx(line)
    assert event is not None
    assert event["log_type"] == "nginx"
    assert event["ip"] == "127.0.0.1"
    assert event["method"] == "GET"
    assert event["path"] == "/admin.php"
    assert event["status"] == 404
    assert event["size"] == 162
    assert event["ua"] == "sqlmap/1.7"
    assert event["ts"] == "2025-03-12T10:23:45"


def test_parse_ssh() -> None:
    """SSH auth 日志通过主通道解析出 IP 与时间。"""
    line = "Mar 12 10:23:45 host sshd[1234]: Failed password for root from 10.0.0.5 port 5512 ssh2"
    event = parse_ssh(line)
    assert event is not None
    assert event["log_type"] == "ssh"
    assert event["ip"] == "10.0.0.5"
    assert event["ts"].endswith("T10:23:45")
    # ssh 日志无 method/path/status/size/ua
    assert event["method"] is None
    assert event["status"] is None


def test_parse_app() -> None:
    """JSON 行格式通过主通道解析出字段。"""
    line = (
        '{"time":"2025-03-12T10:23:45","ip":"10.0.0.5",'
        '"path":" /login","status":401,"msg":"bad password"}'
    )
    event = parse_app(line)
    assert event is not None
    assert event["log_type"] == "app"
    assert event["ip"] == "10.0.0.5"
    assert event["path"] == " /login"
    assert event["status"] == 401
    assert event["ts"] == "2025-03-12T10:23:45"


def test_regex_miss_falls_back_to_split() -> None:
    """正则失配时自动走备通道（分隔符切分）仍能解析。"""
    # nginx：UA 引号内多一个空格导致主正则失配，但按空白切分仍可兜底
    line = (
        '127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] '
        '"GET /admin.php HTTP/1.1" 404 162 "-" "Mozilla 5.0"'
    )
    event = parse_nginx(line)
    assert event is not None
    assert event["ip"] == "127.0.0.1"
    assert event["status"] == 404

    # ssh：把 "port" 字段拼上额外字符导致主正则失配，备通道仍能取到 ip
    line2 = "Mar 12 10:23:45 host sshd[1234]: Failed password for root from 10.0.0.9 port ssh2"
    event2 = parse_ssh(line2)
    assert event2 is not None
    assert event2["ip"] == "10.0.0.9"


def test_iter_events_gzip(tmp_path: Path) -> None:
    """流式读取支持 gzip 透明解压，并正确识别日志类型。"""
    content = (
        '127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] '
        '"GET /admin.php HTTP/1.1" 404 162 "-" "sqlmap/1.7"\n'
        '{"time":"2025-03-12T10:23:45","ip":"10.0.0.5","status":401}\n'
    )
    gz_path = tmp_path / "access.log.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as f:
        f.write(content)

    events = list(iter_events(gz_path))
    assert len(events) == 2
    assert events[0]["log_type"] == "nginx"
    assert events[1]["log_type"] == "app"


def test_sniff_type() -> None:
    """自动识别三种日志类型。"""
    assert sniff_type(
        '127.0.0.1 - - [12/Mar/2025:10:23:45 +0800] "GET / HTTP/1.1" 200 5'
    ) == "nginx"
    assert sniff_type("Mar 12 10:23:45 host sshd[1]: Failed password for x from 1.2.3.4") == "ssh"
    assert sniff_type('{"time":"2025-03-12T10:23:45"}') == "app"
    assert sniff_type("some random garbage line") is None
