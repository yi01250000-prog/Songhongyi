# -*- coding: utf-8 -*-
"""统计分析模块单元测试。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.parser import LogRecord  # noqa: E402
from analyzer.stats import compute_stats, humanize_bytes, humanize_seconds  # noqa: E402

TZ = timezone(timedelta(hours=8))
BASE = datetime(2026, 9, 7, 10, 0, 10, tzinfo=TZ)


def make_record(
    ip: str = "1.1.1.1",
    path: str = "/",
    status: int = 200,
    method: str = "GET",
    ua: str = "Mozilla/5.0",
    offset_seconds: int = 0,
) -> LogRecord:
    return LogRecord(
        ip=ip,
        time=BASE + timedelta(seconds=offset_seconds),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        bytes=100,
        referer="-",
        ua=ua,
        route=path.split("?", 1)[0],
        real_ip=ip,
    )


class StatsTestCase(unittest.TestCase):
    def test_empty_records(self) -> None:
        stats = compute_stats([])
        self.assertEqual(stats["total_requests"], 0)
        self.assertEqual(stats["top_ips"], [])
        self.assertEqual(stats["timeline"], [])

    def test_basic_totals_and_top_lists(self) -> None:
        records = [
            make_record(ip="1.1.1.1", path="/index.html"),
            make_record(ip="1.1.1.1", path="/index.html"),
            make_record(ip="2.2.2.2", path="/about"),
            make_record(ip="2.2.2.2", path="/search?q=log"),
            make_record(ip="3.3.3.3", path="/search?q=python"),
        ]
        stats = compute_stats(records, top_n=2)

        self.assertEqual(stats["total_requests"], 5)
        self.assertEqual(stats["unique_ips"], 3)
        self.assertEqual(stats["unique_urls"], 3)
        self.assertEqual(stats["top_ips"][0]["ip"], "1.1.1.1")
        self.assertEqual(stats["top_ips"][0]["count"], 2)
        self.assertEqual(stats["top_urls"][0], {"url": "/index.html", "count": 2, "percent": 40.0, "errors": 0})
        # /search 的两个不同查询串应聚合为同一路径
        self.assertIn("/search", [item["url"] for item in stats["top_urls"]])

    def test_status_class_and_error_rate(self) -> None:
        records = [
            make_record(status=200),
            make_record(status=301),
            make_record(status=404),
            make_record(status=500),
        ]
        stats = compute_stats(records)
        classes = {item["class"]: item["count"] for item in stats["status_classes"]}
        self.assertEqual(classes["2xx"], 1)
        self.assertEqual(classes["3xx"], 1)
        self.assertEqual(classes["4xx"], 1)
        self.assertEqual(classes["5xx"], 1)
        self.assertEqual(stats["error_count"], 2)
        self.assertAlmostEqual(stats["error_rate"], 0.5)

    def test_method_and_hourly_distribution(self) -> None:
        records = [
            make_record(method="GET"),
            make_record(method="GET"),
            make_record(method="POST"),
        ]
        stats = compute_stats(records)
        methods = {item["method"]: item["count"] for item in stats["methods"]}
        self.assertEqual(methods, {"GET": 2, "POST": 1})
        self.assertEqual(len(stats["hourly"]), 24)
        self.assertEqual(stats["hourly"][10]["count"], 3)

    def test_timeline_minute_bucket_with_gap(self) -> None:
        records = [
            make_record(offset_seconds=0),
            make_record(offset_seconds=300),
        ]
        stats = compute_stats(records)
        self.assertEqual(stats["bucket"]["unit"], "minute")
        self.assertEqual(len(stats["timeline"]), 6)
        self.assertEqual(stats["timeline"][0]["total"], 1)
        self.assertEqual(stats["timeline"][1]["total"], 0)
        self.assertEqual(stats["timeline"][-1]["total"], 1)

    def test_peak_qps(self) -> None:
        records = [make_record(offset_seconds=0) for _ in range(3)]
        stats = compute_stats(records)
        self.assertEqual(stats["peak_qps"], 3)

    def test_humanize_helpers(self) -> None:
        self.assertEqual(humanize_bytes(0), "0 B")
        self.assertEqual(humanize_bytes(1536), "1.50 KB")
        self.assertEqual(humanize_seconds(3661), "1 小时 1 分钟")


if __name__ == "__main__":
    unittest.main()
