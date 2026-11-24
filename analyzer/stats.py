"""统计分析模块：访问趋势、Top IP / URL、状态码分布、请求方法分布等。

所有函数只依赖 ``LogRecord`` 的属性，输出均为可直接 JSON 序列化的字典，
方便 Flask 接口、命令行工具与单元测试复用。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .parser import LogRecord

#: 图表默认取前 N 名
DEFAULT_TOP_N = 10

#: 趋势图最多返回的时间点数量，超过则自动放大时间粒度
MAX_TIMELINE_POINTS = 240

_BUCKET_LABELS = {
    "minute": "按分钟",
    "hour": "按小时",
    "day": "按天",
}

_BUCKET_FORMATS = {
    "minute": "%m-%d %H:%M",
    "hour": "%m-%d %H:00",
    "day": "%m-%d",
}

_LEVEL_LABELS = {
    2: "2xx 成功",
    3: "3xx 重定向",
    4: "4xx 客户端错误",
    5: "5xx 服务端错误",
}


def _is_error(status: int) -> bool:
    return 400 <= status < 600


def humanize_bytes(size: int | float) -> str:
    """把字节数转成人眼友好的单位。"""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


def humanize_seconds(seconds: float) -> str:
    """把秒数转成“x 小时 y 分钟”形式。"""
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days} 天 {hours} 小时"
    if hours:
        return f"{hours} 小时 {minutes} 分钟"
    if minutes:
        return f"{minutes} 分钟 {secs} 秒"
    return f"{secs} 秒"


def _status_class(status: int) -> str:
    return f"{status // 100}xx"


def _bucket_key(moment: datetime, bucket: str) -> datetime:
    if bucket == "minute":
        return moment.replace(second=0, microsecond=0)
    if bucket == "hour":
        return moment.replace(minute=0, second=0, microsecond=0)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def _bucket_step(bucket: str) -> timedelta:
    if bucket == "minute":
        return timedelta(minutes=1)
    if bucket == "hour":
        return timedelta(hours=1)
    return timedelta(days=1)


def _choose_bucket(start: datetime, end: datetime) -> str:
    span = max(0.0, (end - start).total_seconds())
    if span <= 6 * 3600:
        bucket = "minute"
    elif span <= 4 * 86400:
        bucket = "hour"
    else:
        bucket = "day"
    # 时间跨度过大时逐级放大粒度，保证前端图表的点数可控
    while span / _bucket_step(bucket).total_seconds() > MAX_TIMELINE_POINTS and bucket != "day":
        bucket = "hour" if bucket == "minute" else "day"
    return bucket


def build_timeline(
    records: list[LogRecord],
    start: datetime,
    end: datetime,
    bucket: str,
) -> list[dict]:
    """按分钟/小时/天聚合访问量，并补齐没有访问的时间段。"""
    counts: dict[datetime, list[int]] = defaultdict(lambda: [0, 0, 0])
    for record in records:
        key = _bucket_key(record.time, bucket)
        slot = counts[key]
        slot[0] += 1
        if 400 <= record.status < 500:
            slot[1] += 1
        elif 500 <= record.status < 600:
            slot[2] += 1

    points: list[dict] = []
    cursor = _bucket_key(start, bucket)
    last = _bucket_key(end, bucket)
    step = _bucket_step(bucket)
    label_format = _BUCKET_FORMATS[bucket]
    while cursor <= last:
        total, s4xx, s5xx = counts.get(cursor, (0, 0, 0))
        points.append(
            {
                "time": cursor.strftime(label_format),
                "total": total,
                "s4xx": s4xx,
                "s5xx": s5xx,
                "errors": s4xx + s5xx,
            }
        )
        cursor += step
    return points


def compute_stats(
    records: list[LogRecord],
    top_n: int = DEFAULT_TOP_N,
    max_timeline_points: int = MAX_TIMELINE_POINTS,
) -> dict:
    """计算仪表盘需要的全部统计数据。"""
    total = len(records)
    if total == 0:
        return _empty_stats()

    start = min(record.time for record in records)
    end = max(record.time for record in records)
    span_seconds = max(0.0, (end - start).total_seconds())

    bucket = _choose_bucket(start, end)
    timeline = build_timeline(records, start, end, bucket)
    # 极端情况下（如日志跨度过大）截断到最近的点，保证响应体积
    if len(timeline) > max_timeline_points:
        timeline = timeline[-max_timeline_points:]

    ip_stats: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "bytes": 0, "errors": 0}
    )
    url_stats: dict[str, dict] = defaultdict(lambda: {"count": 0, "errors": 0})
    status_counter: Counter[int] = Counter()
    method_counter: Counter[str] = Counter()
    hourly_counter: Counter[int] = Counter()
    per_second: Counter[datetime] = Counter()

    total_bytes = 0
    error_count = 0
    for record in records:
        is_error = _is_error(record.status)

        ip_item = ip_stats[record.ip]
        ip_item["count"] += 1
        ip_item["bytes"] += record.bytes
        if is_error:
            ip_item["errors"] += 1

        url_item = url_stats[record.route]
        url_item["count"] += 1
        if is_error:
            url_item["errors"] += 1

        status_counter[record.status] += 1
        method_counter[record.method] += 1
        hourly_counter[record.time.hour] += 1
        per_second[record.time.replace(microsecond=0)] += 1
        total_bytes += record.bytes
        if is_error:
            error_count += 1

    top_ips = [
        {
            "ip": ip,
            "count": item["count"],
            "percent": round(item["count"] / total * 100, 2),
            "errors": item["errors"],
            "bytes": item["bytes"],
        }
        for ip, item in sorted(
            ip_stats.items(), key=lambda kv: (-kv[1]["count"], kv[0])
        )[:top_n]
    ]

    top_urls = [
        {
            "url": url,
            "count": item["count"],
            "percent": round(item["count"] / total * 100, 2),
            "errors": item["errors"],
        }
        for url, item in sorted(
            url_stats.items(), key=lambda kv: (-kv[1]["count"], kv[0])
        )[:top_n]
    ]

    status_codes = [
        {
            "code": code,
            "count": count,
            "percent": round(count / total * 100, 2),
            "class": _status_class(code),
        }
        for code, count in sorted(status_counter.items())
    ]

    status_classes = []
    for digit in (2, 3, 4, 5):
        count = sum(
            value for code, value in status_counter.items() if code // 100 == digit
        )
        status_classes.append(
            {
                "class": f"{digit}xx",
                "name": _LEVEL_LABELS[digit],
                "count": count,
                "percent": round(count / total * 100, 2),
            }
        )

    methods = [
        {"method": method, "count": count}
        for method, count in sorted(
            method_counter.items(), key=lambda kv: (-kv[1], kv[0])
        )
    ]

    hourly = [
        {"hour": f"{hour:02d}:00", "count": hourly_counter.get(hour, 0)}
        for hour in range(24)
    ]

    peak_qps = max(per_second.values()) if per_second else 0
    peak_minute = max(point["total"] for point in timeline) if timeline else 0
    avg_qps = round(total / span_seconds, 3) if span_seconds > 0 else float(total)

    return {
        "total_requests": total,
        "unique_ips": len(ip_stats),
        "unique_urls": len(url_stats),
        "total_bytes": total_bytes,
        "human_bytes": humanize_bytes(total_bytes),
        "avg_bytes": round(total_bytes / total, 1),
        "error_count": error_count,
        "error_rate": round(error_count / total, 4),
        "success_rate": round((total - error_count) / total, 4),
        "first_time": start.strftime("%Y-%m-%d %H:%M:%S"),
        "last_time": end.strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": start.strftime("%z"),
        "span_seconds": int(span_seconds),
        "span_label": humanize_seconds(span_seconds),
        "avg_qps": avg_qps,
        "peak_qps": peak_qps,
        "peak_bucket_requests": peak_minute,
        "bucket": {"unit": bucket, "label": _BUCKET_LABELS[bucket]},
        "timeline": timeline,
        "top_ips": top_ips,
        "top_urls": top_urls,
        "status_codes": status_codes,
        "status_classes": status_classes,
        "methods": methods,
        "hourly": hourly,
    }


def _empty_stats() -> dict:
    return {
        "total_requests": 0,
        "unique_ips": 0,
        "unique_urls": 0,
        "total_bytes": 0,
        "human_bytes": "0 B",
        "avg_bytes": 0,
        "error_count": 0,
        "error_rate": 0.0,
        "success_rate": 0.0,
        "first_time": "",
        "last_time": "",
        "timezone": "",
        "span_seconds": 0,
        "span_label": "0 秒",
        "avg_qps": 0.0,
        "peak_qps": 0,
        "peak_bucket_requests": 0,
        "bucket": {"unit": "hour", "label": _BUCKET_LABELS["hour"]},
        "timeline": [],
        "top_ips": [],
        "top_urls": [],
        "status_codes": [],
        "status_classes": [],
        "methods": [],
        "hourly": [],
    }
