"""服务层：解析 → 统计 → 异常检测，输出统一的 JSON 结构。

Flask 接口、命令行工具与单元测试都调用这里，避免业务逻辑散落在路由中。
"""

from __future__ import annotations

import os
import time
from datetime import datetime

from .detector import detect_anomalies, get_engine
from .parser import LogParser, format_labels
from .stats import compute_stats, humanize_bytes


def analyze_file(
    path: str,
    filename: str | None = None,
    source: str = "upload",
    top_n: int = 10,
) -> dict:
    """分析一份日志文件，返回 ``{"meta", "stats", "anomalies"}``。"""
    started = time.perf_counter()

    parser = LogParser()
    parse_result = parser.parse_file(path)
    stats = compute_stats(parse_result.records, top_n=top_n)
    anomalies = detect_anomalies(parse_result.records)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    size_bytes = os.path.getsize(path)
    meta = {
        "filename": filename or os.path.basename(path),
        "source": source,
        "size_bytes": size_bytes,
        "size_label": humanize_bytes(size_bytes),
        "total_lines": parse_result.total_lines,
        "parsed_lines": parse_result.parsed_lines,
        "failed_lines": parse_result.failed_lines,
        "success_rate": parse_result.success_rate,
        "encoding": parse_result.encoding,
        "parse_ms": parse_result.elapsed_ms,
        "analyze_ms": elapsed_ms,
        "format_usage": parse_result.format_usage,
        "failed_samples": parse_result.failed_samples,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rules_version": get_engine().version,
        "rule_count": len(get_engine().rules),
    }
    return {"meta": meta, "stats": stats, "anomalies": anomalies}


def rules_payload() -> dict:
    """给前端“检测规则”面板使用的完整配置。"""
    engine = get_engine()
    payload = engine.as_config()
    payload["formats"] = format_labels()
    return payload
