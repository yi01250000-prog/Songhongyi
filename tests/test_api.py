# -*- coding: utf-8 -*-
"""Flask 接口测试（使用 Flask 自带的 test client，不启动真实端口）。"""

from __future__ import annotations

import io
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as app_module  # noqa: E402


@unittest.skipUnless(os.path.exists(app_module.DEMO_LOG), "演示日志不存在，跳过接口测试")
class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        app_module.app.config.update(TESTING=True)
        cls.client = app_module.app.test_client()
        response = cls.client.post("/api/demo")
        if response.status_code != 200:
            raise unittest.SkipTest("演示日志加载失败，跳过接口测试")

    def test_index_page(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("网站访问日志可视化分析工具", html)
        self.assertIn("trendChart", html)
        self.assertIn("echarts.min.js", html)

    def test_health(self) -> None:
        response = self.client.get("/api/health")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertTrue(data["demo_available"])

    def test_stats(self) -> None:
        response = self.client.get("/api/stats")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["stats"]["total_requests"], 10000)
        self.assertGreater(data["stats"]["unique_ips"], 10)
        self.assertEqual(len(data["stats"]["timeline"]), 24)
        self.assertIn("combined", data["meta"]["format_usage"])

    def test_anomalies_pagination_and_filter(self) -> None:
        response = self.client.get("/api/anomalies?page=1&page_size=5")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data["items"]), 5)
        self.assertGreater(data["total"], 100)
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["summary"]["total"], data["total"])

        filtered = self.client.get("/api/anomalies?level=high&page_size=10").get_json()
        self.assertTrue(filtered["items"])
        self.assertTrue(all(item["level"] == "high" for item in filtered["items"]))

        keyword = self.client.get("/api/anomalies?keyword=sqlmap&page_size=10").get_json()
        self.assertTrue(keyword["items"])
        self.assertTrue(all("sqlmap" in item["ua"].lower() for item in keyword["items"]))

    def test_rules_config(self) -> None:
        response = self.client.get("/api/rules")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(data["rules"]), 15)
        self.assertIn("high_freq_per_minute", data["thresholds"])
        self.assertTrue(data["formats"])

    def test_rules_reload(self) -> None:
        response = self.client.post("/api/rules/reload")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["rule_count"], 15)

    def test_export_csv(self) -> None:
        response = self.client.get("/api/anomalies/export?level=high")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["Content-Type"])
        self.assertTrue(response.data.startswith(b"\xef\xbb\xbf"))
        text = response.data.decode("utf-8-sig")
        self.assertIn("命中规则", text)
        self.assertGreater(len(text.splitlines()), 10)

    def test_upload_log(self) -> None:
        content = (
            '127.0.0.1 - - [07/Sep/2026:10:00:00 +0800] "GET /index.html HTTP/1.1" '
            '200 512 "-" "Mozilla/5.0"\n'
            '203.0.113.5 - - [07/Sep/2026:10:00:01 +0800] "GET /missing HTTP/1.1" '
            '404 168 "-" "Mozilla/5.0"\n'
        ).encode("utf-8")
        try:
            response = self.client.post(
                "/api/upload",
                data={"file": (io.BytesIO(content), "test_access.log")},
                content_type="multipart/form-data",
            )
            data = response.get_json()
            self.assertEqual(response.status_code, 200)
            self.assertTrue(data["ok"])
            self.assertEqual(data["meta"]["parsed_lines"], 2)
            self.assertEqual(data["meta"]["filename"], "test_access.log")
        finally:
            self.client.post("/api/demo")

    def test_upload_rejects_bad_extension(self) -> None:
        response = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"hello"), "payload.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_upload_rejects_unparseable_file(self) -> None:
        response = self.client.post(
            "/api/upload",
            data={"file": (io.BytesIO(b"not a log line\nanother bad line\n"), "bad.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 422)
        self.assertFalse(response.get_json()["ok"])

    def test_api_404_returns_json(self) -> None:
        response = self.client.get("/api/not-exists")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
