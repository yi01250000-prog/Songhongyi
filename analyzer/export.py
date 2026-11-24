"""CSV 导出模块：把异常告警渲染成 Excel 可直接打开的 CSV（UTF-8 BOM）。"""

from __future__ import annotations

import csv
import io

from .detector import LEVEL_LABELS

CSV_HEADERS = [
    "序号",
    "时间",
    "等级",
    "来源",
    "IP",
    "请求方法",
    "URL",
    "状态码",
    "命中规则",
    "规则编号",
    "User-Agent",
    "检测说明",
]


def _safe_cell(value) -> str:
    """防止 CSV 公式注入：以 = + - @ 开头的文本前加单引号。"""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def render_events_csv(events: list[dict]) -> bytes:
    """返回带 BOM 的 CSV 字节串，中文在 Excel 中不乱码。"""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADERS)
    for index, event in enumerate(events, 1):
        writer.writerow(
            [
                index,
                _safe_cell(event.get("time")),
                LEVEL_LABELS.get(event["level"], event["level"]),
                "统计检测" if event["source"] == "statistic" else "规则命中",
                _safe_cell(event.get("ip")),
                _safe_cell(event.get("method")),
                _safe_cell(event.get("path")),
                event.get("status", ""),
                _safe_cell(
                    "、".join(rule.get("name", "") for rule in event.get("rules", []))
                ),
                _safe_cell(
                    "、".join(rule.get("id", "") for rule in event.get("rules", []))
                ),
                _safe_cell(event.get("ua")),
                _safe_cell(event.get("detail")),
            ]
        )
    return buffer.getvalue().encode("utf-8-sig")
