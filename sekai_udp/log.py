# https://github.com/nonebot/nonebot2/blob/master/nonebot/log.py

import inspect
import logging
import sys
from typing import TYPE_CHECKING

import loguru

if TYPE_CHECKING:
    from loguru import Logger, Record

logger_id = -1

logger: "Logger" = loguru.logger

# https://loguru.readthedocs.io/en/stable/overview.html#entirely-compatible-with-standard-logging
class LoguruHandler(logging.Handler):  # pragma: no cover
    """logging 与 loguru 之间的桥梁，将 logging 的日志转发到 loguru。"""

    def emit(self, record: logging.LogRecord):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )

_log_level = "INFO"

def set_log_level(level: str | int):
    global _log_level
    _log_level = level


def default_filter(record: "Record"):
    log_level = _log_level
    levelno = logger.level(log_level).no if isinstance(log_level, str) else log_level
    return record["level"].no >= levelno


default_format: str = (
    "<g>{time:HH:mm:ss.SSS}</g> "
    "[<lvl>{level}</lvl>] "
    "<c><u>{name}</u></c> | "
    # "<c>{function}:{line}</c>| "
    "{message}"
)
"""默认日志格式"""

logger.remove()
logger_id = logger.add(
    sys.stdout,
    level=0,
    diagnose=False,
    filter=default_filter,
    format=default_format,
)
colorlog = logger.opt(colors=True)
"""默认日志处理器 id"""


# https://github.com/nonebot/nonebot2/blob/7eaf581762480629e0fba8fa47663b57a5967a76/nonebot/utils.py#L46
import re


def escape_tag(s) -> str:
    """用于记录带颜色日志时转义 `<tag>` 类型特殊标签

    参考: [loguru color 标签](https://loguru.readthedocs.io/en/stable/api/logger.html#color)

    参数:
        s: 需要转义的字符串
    """
    return re.sub(r"</?((?:[fb]g\s)?[^<>\s]*)>", r"\\\g<0>", str(s))


# Dump binary
import base64
from typing import Literal

_dump_view = "bin"

def dump_binary(raw: bytes, view: Literal["hex","bin","base64"] = _dump_view, colored: bool = True):
    if view == "hex":
        text = " ".join(f"{byte:02x}" for byte in raw)
    elif view == "bin":
        text = escape_tag(str(raw))
    elif view == "base64":
        text = escape_tag(base64.b64encode(raw).decode())

    return f"<fg #808080>{text}</>" if colored else text

def set_binary_dump_view(view: Literal["hex","bin","base64"]):
    global _dump_view, dump_binary
    _dump_view = view
