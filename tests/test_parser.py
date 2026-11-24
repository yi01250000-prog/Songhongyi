# -*- coding: utf-8 -*-
"""日志解析模块单元测试。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.parser import LogParser, parse_text  # noqa: E402

COMBINED_LINE = (
    '127.0.0.1 - frank [10/Oct/2023:13:55:36 +0800] "GET /apache_pb.gif HTTP/1.0" '
    '200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
)


class ParserTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.parser = LogParser()

    def test_parse_combined_fields(self) -> None:
        record = self.parser.parse_line(COMBINED_LINE)
        self.assertIsNotNone(record)
        self.assertEqual(record.ip, "127.0.0.1")
        self.assertEqual(record.method, "GET")
        self.assertEqual(record.path, "/apache_pb.gif")
        self.assertEqual(record.protocol, "HTTP/1.0")
        self.assertEqual(record.status, 200)
        self.assertEqual(record.bytes, 2326)
        self.assertEqual(record.referer, "http://www.example.com/start.html")
        self.assertIn("Mozilla/4.08", record.ua)
        self.assertEqual(record.route, "/apache_pb.gif")

    def test_timezone_is_preserved(self) -> None:
        record = self.parser.parse_line(COMBINED_LINE)
        self.assertEqual(record.time.utcoffset(), timedelta(hours=8))
        self.assertEqual(record.time.hour, 13)

    def test_route_strips_query_string(self) -> None:
        line = (
            '203.0.113.7 - - [07/Sep/2026:02:15:44 +0000] "GET /search?q=log&page=2 HTTP/1.1" '
            '200 512 "-" "Mozilla/5.0 (X11; Linux x86_64)"'
        )
        record = self.parser.parse_line(line)
        self.assertEqual(record.path, "/search?q=log&page=2")
        self.assertEqual(record.route, "/search")

    def test_missing_bytes_is_zero(self) -> None:
        line = (
            '203.0.113.8 - - [07/Sep/2026:02:16:00 +0000] "HEAD /index.html HTTP/1.1" '
            '304 - "-" "Mozilla/5.0"'
        )
        record = self.parser.parse_line(line)
        self.assertEqual(record.bytes, 0)

    def test_malformed_request_line_is_tolerated(self) -> None:
        line = (
            '203.0.113.9 - - [07/Sep/2026:02:17:00 +0000] "-" 400 157 "-" "-"'
        )
        record = self.parser.parse_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record.method, "-")
        self.assertEqual(record.path, "-")
        self.assertEqual(record.ua, "-")

    def test_empty_user_agent_is_kept(self) -> None:
        line = (
            '91.240.118.22 - - [07/Sep/2026:01:10:21 +0000] "GET /.env HTTP/1.1" '
            '404 146 "-" ""'
        )
        record = self.parser.parse_line(line)
        self.assertEqual(record.ua, "")

    def test_timed_combined_with_xff(self) -> None:
        line = (
            '10.1.2.3 - - [07/Sep/2026:02:15:44 +0000] "GET /api/data HTTP/1.1" '
            '200 1892 "-" "curl/7.68.0" rt=0.083 xff=203.0.113.9, 10.1.2.1'
        )
        record = self.parser.parse_line(line)
        self.assertIsNotNone(record)
        self.assertEqual(record.real_ip, "203.0.113.9")
        self.assertAlmostEqual(record.response_time, 0.083)

    def test_common_format_has_no_ua(self) -> None:
        line = (
            '203.0.113.10 - - [07/Sep/2026:02:18:00 +0000] "GET /about HTTP/1.0" 200 1024'
        )
        record = self.parser.parse_line(line)
        self.assertEqual(record.ua, "-")
        self.assertEqual(record.referer, "-")

    def test_invalid_line_returns_none(self) -> None:
        self.assertIsNone(self.parser.parse_line("this is not an access log line"))
        self.assertIsNone(self.parser.parse_line(""))

    def test_parse_text_counts_formats(self) -> None:
        text = "\n".join(
            [
                COMBINED_LINE,
                '203.0.113.10 - - [07/Sep/2026:02:18:00 +0000] "GET /about HTTP/1.0" 200 1024',
                "bad line",
            ]
        )
        result = parse_text(self.parser, text)
        self.assertEqual(result.total_lines, 3)
        self.assertEqual(result.parsed_lines, 2)
        self.assertEqual(result.failed_lines, 1)
        self.assertEqual(result.format_usage.get("combined"), 1)
        self.assertEqual(result.format_usage.get("common"), 1)


if __name__ == "__main__":
    unittest.main()
