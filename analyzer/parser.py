"""日志解析模块：把 Nginx / Apache 访问日志的每一行解析成结构化记录。

设计要点
--------
1. 日志格式（正则模板）放在 config/log_formats.json 中，换格式只改配置不改代码；
2. 正则只在加载时编译一次，解析循环中零编译开销；
3. 单行解析失败返回 None，绝不抛异常打断整批解析，并保留失败样本便于排查；
4. 时间用 ``%d/%b/%Y:%H:%M:%S %z`` 解析，保留时区偏移，避免趋势图整体漂移。
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FORMAT_PATH = os.path.join(BASE_DIR, "config", "log_formats.json")

#: 失败样本最多保留多少条（用于页面提示与排查，不占用过多内存）
MAX_FAILED_SAMPLES = 20

#: 字节数、响应耗时等字段缺失时的占位符
MISSING = "-"


@dataclass(slots=True)
class LogRecord:
    """一条结构化的访问日志记录。"""

    ip: str
    time: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes: int
    referer: str
    ua: str
    route: str
    real_ip: str
    response_time: float | None = None

    def to_dict(self) -> dict:
        """转成可 JSON 序列化的字典（时间保留到秒并带时区偏移）。"""
        return {
            "ip": self.ip,
            "real_ip": self.real_ip,
            "time": self.time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "method": self.method,
            "path": self.path,
            "protocol": self.protocol,
            "status": self.status,
            "bytes": self.bytes,
            "referer": self.referer,
            "ua": self.ua,
            "route": self.route,
            "response_time": self.response_time,
        }


@dataclass(slots=True)
class ParseResult:
    """整份日志的解析结果。"""

    records: list[LogRecord] = field(default_factory=list)
    total_lines: int = 0
    failed_lines: int = 0
    failed_samples: list[dict] = field(default_factory=list)
    format_usage: dict[str, int] = field(default_factory=dict)
    encoding: str = "utf-8"
    elapsed_ms: float = 0.0

    @property
    def parsed_lines(self) -> int:
        return len(self.records)

    @property
    def success_rate(self) -> float:
        if not self.total_lines:
            return 0.0
        return round(self.parsed_lines / self.total_lines, 4)


class LogParser:
    """按配置中的正则模板解析访问日志。"""

    def __init__(self, formats_path: str | None = None) -> None:
        self.formats_path = formats_path or DEFAULT_FORMAT_PATH
        with open(self.formats_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
        self.time_format: str = config.get("time_format", "%d/%b/%Y:%H:%M:%S %z")
        # 一次性编译所有模板，解析时直接复用
        self.formats: list[tuple[str, re.Pattern[str]]] = [
            (item["name"], re.compile(item["pattern"]))
            for item in config["formats"]
        ]
        if not self.formats:
            raise ValueError("日志格式配置为空，请检查 config/log_formats.json")

    # ------------------------------------------------------------------
    # 单行解析
    # ------------------------------------------------------------------
    def parse_line(self, line: str) -> LogRecord | None:
        """解析一行日志；无法识别时返回 None。"""
        record, _ = self._parse_line(line)
        return record

    def _parse_line(self, line: str) -> tuple[LogRecord | None, str | None]:
        text = line.rstrip("\r\n")
        if not text.strip():
            return None, None
        for name, pattern in self.formats:
            match = pattern.match(text)
            if not match:
                continue
            try:
                return self._build_record(match), name
            except (ValueError, KeyError):
                # 该模板虽然结构匹配，但时间/状态码等字段非法，尝试下一个模板
                continue
        return None, None

    def _build_record(self, match: re.Match[str]) -> LogRecord:
        data = match.groupdict()

        # 1) 时间：带时区偏移，跨时区日志不会漂移
        dt = datetime.strptime(data["time"], self.time_format)

        # 2) 请求行拆成 method / path / protocol（请求行可能整体是 "-"）
        request = (data.get("request") or "").strip()
        parts = request.split()
        if len(parts) >= 3:
            method, path, protocol = parts[0], parts[1], " ".join(parts[2:])
        elif len(parts) == 2:
            method, path, protocol = parts[0], parts[1], MISSING
        elif len(parts) == 1 and parts[0] != MISSING:
            method, path, protocol = MISSING, parts[0], MISSING
        else:
            method = path = protocol = MISSING
        method = method.upper()

        # 3) 状态码 / 字节数（字节数可能是 "-"）
        status = int(data["status"])
        raw_bytes = (data.get("bytes") or MISSING).strip()
        byte_count = int(raw_bytes) if raw_bytes.isdigit() else 0

        # 4) 统计用 URL：去掉查询串，避免同一路径因参数不同被拆成上千条
        route = path.split("?", 1)[0] or "/"

        # 5) X-Forwarded-For：反代场景取第一个 IP 作为真实客户端
        xff = (data.get("xff") or "").strip()
        real_ip = xff.split(",")[0].strip() if xff and xff != MISSING else data["ip"]

        # 6) 可选字段：Referer / UA / 响应耗时
        referer = data.get("referer")
        referer = referer.strip() if referer is not None else MISSING
        ua = data.get("ua")
        # 注意：common 格式没有 UA 字段时记 "-"，只有 combined 里写成 "" 才视为空 UA
        ua = ua.strip() if ua is not None else MISSING
        raw_rt = (data.get("rt") or "").strip()
        try:
            response_time = float(raw_rt) if raw_rt else None
        except ValueError:
            response_time = None

        return LogRecord(
            ip=data["ip"],
            time=dt,
            method=method,
            path=path,
            protocol=protocol,
            status=status,
            bytes=byte_count,
            referer=referer,
            ua=ua,
            route=route,
            real_ip=real_ip,
            response_time=response_time,
        )

    # ------------------------------------------------------------------
    # 文件解析
    # ------------------------------------------------------------------
    def parse_file(self, path: str) -> ParseResult:
        """逐行解析整个日志文件（内存占用与文件大小无关）。"""
        started = time.perf_counter()
        encoding = detect_encoding(path)
        result = ParseResult(encoding=encoding)
        usage: Counter[str] = Counter()

        with open(path, "r", encoding=encoding, errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                result.total_lines += 1
                record, fmt = self._parse_line(line)
                if record is None:
                    result.failed_lines += 1
                    if len(result.failed_samples) < MAX_FAILED_SAMPLES:
                        result.failed_samples.append(
                            {"line": lineno, "text": line.strip()[:160]}
                        )
                else:
                    result.records.append(record)
                    if fmt:
                        usage[fmt] += 1

        result.format_usage = dict(usage)
        result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return result


def detect_encoding(path: str) -> str:
    """抽样判断日志编码：优先 UTF-8，其次 GB18030（兼容 GBK/GB2312）。"""
    with open(path, "rb") as fh:
        sample = fh.read(65536)
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    for encoding in ("utf-8", "gb18030"):
        try:
            sample.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "latin-1"


def iter_lines(text: str) -> Iterator[str]:
    """把多行文本拆成行，便于单元测试或接口直接传文本。"""
    for line in text.splitlines():
        yield line


def parse_text(parser: LogParser, text: str) -> ParseResult:
    """解析内存中的多行日志文本（测试与脚本使用）。"""
    started = time.perf_counter()
    result = ParseResult(encoding="utf-8")
    usage: Counter[str] = Counter()
    for lineno, line in enumerate(iter_lines(text), 1):
        if not line.strip():
            continue
        result.total_lines += 1
        record, fmt = parser._parse_line(line)
        if record is None:
            result.failed_lines += 1
            if len(result.failed_samples) < MAX_FAILED_SAMPLES:
                result.failed_samples.append(
                    {"line": lineno, "text": line.strip()[:160]}
                )
        else:
            result.records.append(record)
            if fmt:
                usage[fmt] += 1
    result.format_usage = dict(usage)
    result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return result


def format_labels(formats_path: str | None = None) -> list[dict]:
    """读取格式配置，返回给前端/报告使用的名称与说明。"""
    with open(formats_path or DEFAULT_FORMAT_PATH, "r", encoding="utf-8") as fh:
        config = json.load(fh)
    return [
        {"name": item["name"], "label": item.get("label", item["name"])}
        for item in config["formats"]
    ]
