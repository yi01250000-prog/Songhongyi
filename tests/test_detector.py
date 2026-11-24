# -*- coding: utf-8 -*-
"""异常检测模块单元测试：签名规则 + 统计检测。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.detector import (  # noqa: E402
    LEVEL_WEIGHT,
    RuleEngine,
    detect_anomalies,
    detect_bruteforce,
    detect_error_rate,
    detect_high_frequency,
    detect_scan,
    detect_server_error_burst,
    get_engine,
)
from analyzer.parser import LogRecord  # noqa: E402

TZ = timezone(timedelta(hours=8))
BASE = datetime(2026, 9, 7, 10, 0, 0, tzinfo=TZ)


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


class RuleEngineTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RuleEngine()

    def rule_ids(self, record: LogRecord) -> set[str]:
        return {rule.id for rule in self.engine.match(record)}

    def test_sql_injection_variants(self) -> None:
        self.assertIn(
            "SQLI-001",
            self.rule_ids(make_record(path="/news.php?id=1%20UnIoN/**/SeLeCt%20NULL")),
        )
        self.assertIn(
            "SQLI-001",
            self.rule_ids(make_record(path="/api?x=1 UNION ALL SELECT password FROM users")),
        )
        self.assertIn(
            "SQLI-002",
            self.rule_ids(make_record(path="/login?u=admin%27%20or%20%271%27=%271")),
        )
        self.assertIn(
            "SQLI-004",
            self.rule_ids(make_record(path="/item.php?id=1%20AND%20SLEEP(5)")),
        )
        self.assertIn(
            "SQLI-005",
            self.rule_ids(make_record(path="/news.php?id=1 UNION SELECT table_name FROM information_schema.tables")),
        )

    def test_path_traversal_and_sensitive_path(self) -> None:
        self.assertIn("TRAV-001", self.rule_ids(make_record(path="/download?file=../../etc/passwd")))
        self.assertIn("TRAV-002", self.rule_ids(make_record(path="/download?file=../../etc/passwd")))
        self.assertIn("TRAV-001", self.rule_ids(make_record(path="/download?file=..%2f..%2fetc%2fpasswd")))
        self.assertIn("SENS-001", self.rule_ids(make_record(path="/.git/config")))

    def test_command_injection_xss_and_lfi(self) -> None:
        self.assertIn("CMDI-001", self.rule_ids(make_record(path="/ping?host=127.0.0.1;cat%20/etc/passwd")))
        self.assertIn("CMDI-001", self.rule_ids(make_record(path="/ping?host=127.0.0.1|whoami")))
        self.assertIn("XSS-001", self.rule_ids(make_record(path="/comment?text=<script>alert(1)</script>")))
        self.assertIn(
            "LFI-001",
            self.rule_ids(make_record(path="/util?file=php://filter/convert.base64-encode/resource=index.php")),
        )

    def test_tool_and_empty_user_agent(self) -> None:
        self.assertIn("UA-001", self.rule_ids(make_record(ua="sqlmap/1.7.2#stable")))
        self.assertIn("UA-003", self.rule_ids(make_record(ua="")))
        self.assertNotIn("UA-003", self.rule_ids(make_record(ua="Mozilla/5.0")))

    def test_clean_request_has_no_hit(self) -> None:
        self.assertEqual(self.rule_ids(make_record(path="/index.html", ua="Mozilla/5.0")), set())

    def test_url_encoding_and_case_are_handled(self) -> None:
        hits = self.rule_ids(make_record(path="/search?q=%3Cscript%3Ealert(1)%3C/script%3E"))
        self.assertIn("XSS-001", hits)


class StatisticalDetectorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.thresholds = get_engine().thresholds

    def test_high_frequency(self) -> None:
        records = [make_record(ip="9.9.9.9", offset_seconds=i) for i in range(70)]
        findings = detect_high_frequency(records, self.thresholds)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ip"], "9.9.9.9")
        self.assertGreaterEqual(findings[0]["evidence"]["peak_requests_per_minute"], 60)

    def test_error_rate(self) -> None:
        records = [make_record(ip="8.8.8.8", status=404, offset_seconds=i) for i in range(30)]
        records += [make_record(ip="8.8.8.8", status=200, offset_seconds=100 + i) for i in range(10)]
        findings = detect_error_rate(records, self.thresholds)
        self.assertEqual(len(findings), 1)
        self.assertAlmostEqual(findings[0]["evidence"]["error_rate"], 0.75)

    def test_scan_detection(self) -> None:
        records = [
            make_record(ip="7.7.7.7", path=f"/scan/{index}.php", status=404, offset_seconds=index)
            for index in range(40)
        ]
        findings = detect_scan(records, self.thresholds)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["distinct_paths"], 40)

    def test_bruteforce_detection(self) -> None:
        records = [
            make_record(ip="6.6.6.6", path="/admin/login", method="POST", status=401, offset_seconds=i)
            for i in range(10)
        ]
        records.append(
            make_record(ip="6.6.6.6", path="/admin/login", method="POST", status=200, offset_seconds=20)
        )
        findings = detect_bruteforce(records, self.thresholds)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["evidence"]["bruteforce_success"])

    def test_server_error_burst(self) -> None:
        records = [make_record(ip="5.5.5.5", status=500, offset_seconds=i) for i in range(25)]
        findings = detect_server_error_burst(records, self.thresholds)
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings[0]["evidence"]["server_errors_per_minute"], 20)


class DetectAnomaliesTestCase(unittest.TestCase):
    def test_events_and_summary(self) -> None:
        records = [
            make_record(ip="203.0.113.99", path="/news?id=1%20UNION%20SELECT%20NULL", ua="sqlmap/1.7.2")
        ]
        records += [make_record(ip="9.9.9.9", offset_seconds=i) for i in range(70)]
        result = detect_anomalies(records)

        summary = result["summary"]
        self.assertGreater(summary["total"], 0)
        self.assertGreaterEqual(summary["high"], 1)
        self.assertIn("SQLI-001", [item["id"] for item in summary["by_rule"]])

        # 同一等级下统计检测的聚合事件应排在单条规则命中之前
        level_order = [LEVEL_WEIGHT[event["level"]] for event in result["events"]]
        self.assertEqual(level_order, sorted(level_order))
        high_events = [event for event in result["events"] if event["level"] == "high"]
        self.assertEqual(high_events[0]["source"], "statistic")

    def test_event_fields_complete(self) -> None:
        result = detect_anomalies(
            [make_record(ip="203.0.113.99", path="/download?file=../../etc/passwd", ua="sqlmap")]
        )
        event = result["events"][0]
        for key in ("id", "time", "level", "source", "ip", "method", "path", "status", "rules", "detail"):
            self.assertIn(key, event)
        self.assertGreaterEqual(len(event["rules"]), 1)


if __name__ == "__main__":
    unittest.main()
