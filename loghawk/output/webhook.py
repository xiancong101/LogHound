"""Webhook 告警输出：POST JSON 到配置的 URL，带指数退避重试。

重试策略：最多 3 次，每次失败后按 ``base_delay * 2 ** attempt`` 秒退避
（即 1s、2s、4s），3 次仍失败则放弃并记录错误。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

from .base import Alert, OutputBackend

DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0  # 秒


class WebhookOutput(OutputBackend):
    """通过 HTTP POST 将告警 JSON 发送到 Webhook 地址。"""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_delay: float = DEFAULT_BASE_DELAY,
    ) -> None:
        """初始化。

        参数：
            url: 目标 Webhook 地址。
            timeout: 单次请求超时（秒）。
            max_retries: 最大重试次数（含首次共 max_retries 次尝试）。
            base_delay: 指数退避的基准延迟（秒）。
        """
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_delay = base_delay

    def send(self, alert: Alert) -> None:
        """发送一条告警，失败时按指数退避重试。"""
        payload = alert.to_json().encode("utf-8")
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                self._post(payload)
                return  # 成功
            except Exception as exc:  # noqa: BLE001 - 网络异常统一兜底
                last_error = exc
                # 最后一次尝试不再退避等待
                if attempt < self.max_retries - 1:
                    delay = self.base_delay * (2 ** attempt)
                    time.sleep(delay)

        # 全部失败：打印错误（不抛异常，避免中断检测流程）
        print(
            f"[webhook] 发送告警失败（已重试 {self.max_retries} 次）: "
            f"{self.url} -> {last_error}",
            file=__import__("sys").stderr,
        )

    def _post(self, payload: bytes) -> None:
        """执行一次 HTTP POST。"""
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            # 2xx 视为成功；其他状态码抛异常触发重试
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, "webhook 返回错误", resp.headers, None
                )
