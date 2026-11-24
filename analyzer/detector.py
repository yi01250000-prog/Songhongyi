"""异常检测模块：可配置签名规则引擎 + 统计型异常检测。

规则全部写在 config/rules.json 中，修改规则或阈值后调用 reload 即可生效，
不需要改动任何 Python 代码 —— 对应任务书“规则可配置（JSON）”的要求。
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .parser import LogRecord

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES_PATH = os.path.join(BASE_DIR, "config", "rules.json")

LEVELS = ("high", "medium", "low")
LEVEL_LABELS = {"high": "高危", "medium": "中危", "low": "低危"}
LEVEL_WEIGHT = {"high": 0, "medium": 1, "low": 2}

RULE_TYPES = {"path_pattern", "path_keywords", "ua_keywords", "ua_empty"}

#: 统计型检测在告警列表中的“伪规则”，让前端可以统一展示与统计
STAT_RULES: dict[str, dict] = {
    "high_frequency": {
        "id": "STAT-FREQ",
        "name": "单 IP 高频访问",
        "category": "high_frequency",
        "level": "high",
    },
    "error_rate": {
        "id": "STAT-ERR",
        "name": "错误率异常",
        "category": "error_rate",
        "level": "medium",
    },
    "scan": {
        "id": "STAT-SCAN",
        "name": "目录 / 漏洞扫描",
        "category": "scan",
        "level": "high",
    },
    "bruteforce": {
        "id": "STAT-BF",
        "name": "暴力破解登录",
        "category": "bruteforce",
        "level": "high",
    },
    "server_error": {
        "id": "STAT-5XX",
        "name": "5xx 错误突增",
        "category": "server_error",
        "level": "medium",
    },
}


class RuleConfigError(ValueError):
    """规则配置不合法时抛出。"""


@dataclass(slots=True)
class Rule:
    """一条签名检测规则。"""

    id: str
    name: str
    category: str
    level: str
    type: str
    pattern: Any
    description: str = ""
    mitre: str = ""
    keywords: tuple[str, ...] = ()
    compiled: re.Pattern[str] | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "level": self.level,
            "type": self.type,
            "pattern": self.pattern,
            "description": self.description,
            "mitre": self.mitre,
        }


def decode_path(path: str) -> str:
    """URL 解码并转小写，对抗 %27、%20、大小写混淆等变形。"""
    try:
        return urllib.parse.unquote(path).lower()
    except Exception:  # 极端畸形输入不应影响整批检测
        return path.lower()


def _parse_level(value: str, rule_id: str) -> str:
    level = str(value or "").strip().lower()
    if level not in LEVELS:
        raise RuleConfigError(f"规则 {rule_id} 的 level 必须是 high/medium/low")
    return level


class RuleEngine:
    """加载 JSON 规则 → 编译正则 → 对单条记录执行匹配。"""

    def __init__(self, rules_path: str | None = None) -> None:
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        with open(self.rules_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)

        self.version = str(config.get("version", "1.0"))
        self.categories: dict[str, str] = dict(config.get("categories", {}))
        self.thresholds: dict[str, Any] = dict(config.get("thresholds", {}))
        self.rules: list[Rule] = []

        for item in config.get("rules", []):
            self.rules.append(self._build_rule(item))

        if not self.rules:
            raise RuleConfigError("规则配置为空，请检查 config/rules.json")

        self.path_rules = [
            rule for rule in self.rules if rule.type in ("path_pattern", "path_keywords")
        ]
        self.ua_rules = [rule for rule in self.rules if rule.type == "ua_keywords"]
        self.empty_ua_rules = [rule for rule in self.rules if rule.type == "ua_empty"]

    @staticmethod
    def _build_rule(item: dict) -> Rule:
        rule_id = str(item.get("id", "")).strip()
        rule_type = str(item.get("type", "")).strip()
        if not rule_id:
            raise RuleConfigError("存在缺少 id 的规则")
        if rule_type not in RULE_TYPES:
            raise RuleConfigError(f"规则 {rule_id} 的 type 不受支持：{rule_type}")

        pattern = item.get("pattern", "")
        keywords: tuple[str, ...] = ()
        compiled: re.Pattern[str] | None = None

        if rule_type in ("path_pattern", "ua_keywords") and not isinstance(pattern, (str, list)):
            raise RuleConfigError(f"规则 {rule_id} 的 pattern 格式错误")
        if rule_type == "path_pattern":
            if not isinstance(pattern, str) or not pattern:
                raise RuleConfigError(f"规则 {rule_id} 需要非空的正则 pattern")
            try:
                compiled = re.compile(pattern, re.I)
            except re.error as exc:
                raise RuleConfigError(f"规则 {rule_id} 正则编译失败：{exc}") from exc
        if rule_type == "path_keywords":
            keywords = _normalize_keywords(rule_id, pattern)
        if rule_type == "ua_keywords":
            keywords = _normalize_keywords(rule_id, pattern)

        return Rule(
            id=rule_id,
            name=str(item.get("name", rule_id)),
            category=str(item.get("category", "other")),
            level=_parse_level(item.get("level", ""), rule_id),
            type=rule_type,
            pattern=pattern,
            description=str(item.get("description", "")),
            mitre=str(item.get("mitre", "")),
            keywords=keywords,
            compiled=compiled,
        )

    # ------------------------------------------------------------------
    # 匹配
    # ------------------------------------------------------------------
    def match(self, record: LogRecord, decoded_path: str | None = None) -> list[Rule]:
        """返回该记录命中的所有规则（按配置顺序）。"""
        path = decoded_path if decoded_path is not None else decode_path(record.path)
        ua = (record.ua or "").lower()
        hits: list[Rule] = []

        for rule in self.path_rules:
            if rule.type == "path_pattern":
                if rule.compiled is not None and rule.compiled.search(path):
                    hits.append(rule)
            elif rule.keywords and any(keyword in path for keyword in rule.keywords):
                hits.append(rule)

        for rule in self.ua_rules:
            if rule.keywords and any(keyword in ua for keyword in rule.keywords):
                hits.append(rule)

        if not ua.strip():
            hits.extend(self.empty_ua_rules)

        return hits

    def category_label(self, category: str) -> str:
        return self.categories.get(category, category)

    def as_config(self) -> dict:
        """返回给前端 /api/rules 的配置视图（不含编译后的对象）。"""
        return {
            "version": self.version,
            "categories": self.categories,
            "thresholds": self.thresholds,
            "rules": [rule.to_dict() for rule in self.rules],
        }


def _normalize_keywords(rule_id: str, pattern: Any) -> tuple[str, ...]:
    if isinstance(pattern, str):
        raw = [item.strip() for item in pattern.split(",")]
    elif isinstance(pattern, list):
        raw = [str(item).strip() for item in pattern]
    else:
        raise RuleConfigError(f"规则 {rule_id} 的 pattern 应为数组或逗号分隔字符串")
    keywords = tuple(item.lower() for item in raw if item)
    if not keywords:
        raise RuleConfigError(f"规则 {rule_id} 的关键词列表不能为空")
    return keywords


# ----------------------------------------------------------------------
# 规则引擎单例：进程内只加载一次，支持热加载
# ----------------------------------------------------------------------
_engine: RuleEngine | None = None
_engine_lock = threading.Lock()


def get_engine(reload: bool = False) -> RuleEngine:
    global _engine
    with _engine_lock:
        if _engine is None or reload:
            _engine = RuleEngine()
        return _engine


def reload_engine() -> RuleEngine:
    """从磁盘重新加载规则（前端“重载规则”按钮调用）。"""
    return get_engine(reload=True)


# ----------------------------------------------------------------------
# 统计型检测
# ----------------------------------------------------------------------
def _threshold_int(thresholds: dict, key: str, default: int) -> int:
    try:
        return int(thresholds.get(key, default))
    except (TypeError, ValueError):
        return default


def _threshold_float(thresholds: dict, key: str, default: float) -> float:
    try:
        return float(thresholds.get(key, default))
    except (TypeError, ValueError):
        return default


def _window_max_count(times: list[datetime], window_seconds: int) -> tuple[int, datetime | None, datetime | None]:
    """滑动窗口：返回任意 window_seconds 内的最大请求数及其起止时间。"""
    if not times:
        return 0, None, None
    times = sorted(times)
    best = 0
    best_start: datetime | None = None
    best_end: datetime | None = None
    left = 0
    for right, moment in enumerate(times):
        while (moment - times[left]).total_seconds() > window_seconds:
            left += 1
        count = right - left + 1
        if count > best:
            best = count
            best_start = times[left]
            best_end = moment
    return best, best_start, best_end


def detect_high_frequency(records: list[LogRecord], thresholds: dict) -> list[dict]:
    """单 IP 高频访问：任意 60 秒内请求数超过阈值。"""
    threshold = _threshold_int(thresholds, "high_freq_per_minute", 80)
    min_requests = _threshold_int(thresholds, "high_freq_min_requests", 20)

    per_ip: dict[str, list[datetime]] = defaultdict(list)
    for record in records:
        per_ip[record.ip].append(record.time)

    findings: list[dict] = []
    for ip, times in per_ip.items():
        if len(times) < min_requests:
            continue
        peak, peak_start, peak_end = _window_max_count(times, 60)
        if peak >= threshold:
            findings.append(
                {
                    "type": "high_frequency",
                    "ip": ip,
                    "level": "high",
                    "time": peak_start or min(times),
                    "detail": f"任意 60 秒内最多请求 {peak} 次（阈值 {threshold} 次/分钟）",
                    "evidence": {
                        "peak_requests_per_minute": peak,
                        "window_start": peak_start.strftime("%H:%M:%S") if peak_start else "",
                        "window_end": peak_end.strftime("%H:%M:%S") if peak_end else "",
                        "total_requests": len(times),
                    },
                }
            )
    return findings


def detect_error_rate(records: list[LogRecord], thresholds: dict) -> list[dict]:
    """错误率异常：请求总量达到阈值且 4xx/5xx 占比过高。"""
    min_requests = _threshold_int(thresholds, "error_min_requests", 30)
    rate_threshold = _threshold_float(thresholds, "error_rate_threshold", 0.6)

    stats: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "errors": 0, "s4xx": 0, "s5xx": 0, "first": None}
    )
    for record in records:
        item = stats[record.ip]
        item["total"] += 1
        if item["first"] is None:
            item["first"] = record.time
        if 400 <= record.status < 500:
            item["errors"] += 1
            item["s4xx"] += 1
        elif 500 <= record.status < 600:
            item["errors"] += 1
            item["s5xx"] += 1

    findings: list[dict] = []
    for ip, item in stats.items():
        if item["total"] < min_requests:
            continue
        rate = item["errors"] / item["total"]
        if rate < rate_threshold:
            continue
        findings.append(
            {
                "type": "error_rate",
                "ip": ip,
                "level": "medium",
                "time": item["first"],
                "detail": (
                    f"共 {item['total']} 次请求，4xx/5xx 合计 {item['errors']} 次，"
                    f"错误率 {rate:.1%}（阈值 {rate_threshold:.0%}）"
                ),
                "evidence": {
                    "total_requests": item["total"],
                    "error_requests": item["errors"],
                    "s4xx": item["s4xx"],
                    "s5xx": item["s5xx"],
                    "error_rate": round(rate, 3),
                },
            }
        )
    return findings


def detect_scan(records: list[LogRecord], thresholds: dict) -> list[dict]:
    """目录 / 漏洞扫描：同一 IP 大量 404 且命中大量不同路径。"""
    min_paths = _threshold_int(thresholds, "scan_404_paths", 25)
    min_404 = _threshold_int(thresholds, "scan_min_404", 30)

    stats: dict[str, dict] = defaultdict(
        lambda: {"paths": Counter(), "count404": 0, "total": 0, "first": None, "last": None}
    )
    for record in records:
        item = stats[record.ip]
        item["total"] += 1
        if record.status == 404:
            item["count404"] += 1
            item["paths"][record.route] += 1
            if item["first"] is None:
                item["first"] = record.time
            item["last"] = record.time

    findings: list[dict] = []
    for ip, item in stats.items():
        distinct = len(item["paths"])
        if distinct < min_paths or item["count404"] < min_404:
            continue
        findings.append(
            {
                "type": "scan",
                "ip": ip,
                "level": "high",
                "time": item["first"],
                "detail": (
                    f"404 请求 {item['count404']} 次，涉及 {distinct} 个不同的不存在路径，"
                    f"疑似目录/漏洞扫描（阈值 {min_paths} 个路径 / {min_404} 次 404）"
                ),
                "evidence": {
                    "not_found_requests": item["count404"],
                    "distinct_paths": distinct,
                    "total_requests": item["total"],
                    "top_paths": [
                        {"path": path, "count": count}
                        for path, count in item["paths"].most_common(5)
                    ],
                },
            }
        )
    return findings


def detect_bruteforce(records: list[LogRecord], thresholds: dict) -> list[dict]:
    """暴力破解：同一 IP 对登录接口连续失败，且失败后出现成功响应。"""
    fail_threshold = _threshold_int(thresholds, "bruteforce_fails", 8)
    window_minutes = _threshold_int(thresholds, "bruteforce_window_minutes", 15)
    keywords = [
        str(item).lower()
        for item in thresholds.get("login_path_keywords", ["login", "signin", "auth", "admin"])
    ]
    methods = {str(item).upper() for item in thresholds.get("login_methods", ["POST"])}

    per_ip: dict[str, list[LogRecord]] = defaultdict(list)
    for record in records:
        if record.method not in methods:
            continue
        route = record.route.lower()
        if any(keyword in route for keyword in keywords):
            per_ip[record.ip].append(record)

    findings: list[dict] = []
    for ip, requests_list in per_ip.items():
        requests_list.sort(key=lambda item: item.time)
        fails = [item for item in requests_list if item.status in (401, 403, 429)]
        if len(fails) < fail_threshold:
            continue
        peak, peak_start, peak_end = _window_max_count(
            [item.time for item in fails], window_minutes * 60
        )
        if peak < fail_threshold:
            continue
        last_fail_time = fails[-1].time
        success_after = [
            item
            for item in requests_list
            if item.status in (200, 302) and item.time >= last_fail_time
        ]
        success = bool(success_after)
        detail = (
            f"登录接口在 {window_minutes} 分钟内失败 {peak} 次（阈值 {fail_threshold} 次）"
            f"{'，且随后出现状态码 200，疑似爆破成功' if success else '，疑似口令爆破'}"
        )
        findings.append(
            {
                "type": "bruteforce",
                "ip": ip,
                "level": "high",
                "time": peak_start or fails[0].time,
                "detail": detail,
                "evidence": {
                    "failed_attempts": peak,
                    "window_start": peak_start.strftime("%H:%M:%S") if peak_start else "",
                    "window_end": peak_end.strftime("%H:%M:%S") if peak_end else "",
                    "bruteforce_success": success,
                    "target_paths": sorted({item.route for item in requests_list})[:5],
                },
            }
        )
    return findings


def detect_server_error_burst(records: list[LogRecord], thresholds: dict) -> list[dict]:
    """5xx 突增：单位时间内服务端错误数量超过阈值。"""
    burst_threshold = _threshold_int(thresholds, "server_error_burst", 20)
    window_minutes = _threshold_int(thresholds, "server_error_window_minutes", 5)

    minute_counts: Counter[datetime] = Counter()
    minute_ips: dict[datetime, Counter[str]] = defaultdict(Counter)
    for record in records:
        if 500 <= record.status < 600:
            key = record.time.replace(second=0, microsecond=0)
            minute_counts[key] += 1
            minute_ips[key][record.ip] += 1

    findings: list[dict] = []
    for minute, count in sorted(minute_counts.items()):
        if count < burst_threshold:
            continue
        top_ip, top_count = minute_ips[minute].most_common(1)[0]
        findings.append(
            {
                "type": "server_error",
                "ip": top_ip,
                "level": "medium",
                "time": minute,
                "detail": (
                    f"{minute.strftime('%H:%M')} 一分钟内出现 {count} 次 5xx 响应"
                    f"（阈值 {burst_threshold} 次 / {window_minutes} 分钟），主要来源 {top_ip} {top_count} 次"
                ),
                "evidence": {
                    "server_errors_per_minute": count,
                    "minute": minute.strftime("%Y-%m-%d %H:%M"),
                    "top_ip": top_ip,
                    "top_ip_errors": top_count,
                },
            }
        )
    return findings


STAT_DETECTORS = (
    detect_high_frequency,
    detect_error_rate,
    detect_scan,
    detect_bruteforce,
    detect_server_error_burst,
)


def statistical_findings(records: list[LogRecord], thresholds: dict) -> list[dict]:
    findings: list[dict] = []
    for detector in STAT_DETECTORS:
        findings.extend(detector(records, thresholds))
    findings.sort(key=lambda item: (LEVEL_WEIGHT[item["level"]], item["time"]))
    return findings


# ----------------------------------------------------------------------
# 汇总检测
# ----------------------------------------------------------------------
def detect_anomalies(
    records: list[LogRecord],
    engine: RuleEngine | None = None,
) -> dict:
    """执行签名规则 + 统计检测，返回告警事件与汇总信息。"""
    engine = engine or get_engine()
    thresholds = engine.thresholds
    max_events = _threshold_int(thresholds, "max_events", 3000)

    events: list[dict] = []
    rule_hits: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    level_counts: Counter[str] = Counter()
    stat_type_counts: Counter[str] = Counter()
    ip_levels: dict[str, Counter[str]] = defaultdict(Counter)

    # 记录每个 IP 的代表性路径与 UA，供统计型告警展示上下文
    ip_routes: dict[str, Counter[str]] = defaultdict(Counter)
    ip_methods: dict[str, Counter[str]] = defaultdict(Counter)
    ip_status: dict[str, Counter[int]] = defaultdict(Counter)
    ip_ua: dict[str, str] = {}

    for record in records:
        ip_routes[record.ip][record.route] += 1
        ip_methods[record.ip][record.method] += 1
        ip_status[record.ip][record.status] += 1
        if record.ua and record.ua != "-":
            ip_ua.setdefault(record.ip, record.ua)

        hits = engine.match(record)
        if not hits:
            continue

        highest = min(hits, key=lambda rule: LEVEL_WEIGHT[rule.level])
        categories = sorted({rule.category for rule in hits})
        for rule in hits:
            rule_hits[rule.id] += 1
        for category in categories:
            # 同一请求命中多条同类规则时只计一次，保证“告警数”口径一致
            category_counts[category] += 1
        level_counts[highest.level] += 1
        ip_levels[record.ip][highest.level] += 1

        events.append(
            {
                "dt": record.time,
                "time": record.time.strftime("%Y-%m-%d %H:%M:%S"),
                "level": highest.level,
                "source": "rule",
                "ip": record.ip,
                "real_ip": record.real_ip,
                "method": record.method,
                "path": record.path,
                "route": record.route,
                "status": record.status,
                "ua": record.ua,
                "categories": categories,
                "rules": [
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "category": rule.category,
                        "level": rule.level,
                    }
                    for rule in hits
                ],
                "detail": "命中规则：" + "、".join(rule.name for rule in hits),
                "evidence": [
                    {"rule": rule.id, "pattern": rule.pattern, "level": rule.level}
                    for rule in hits
                ],
            }
        )

    # 统计型检测：同一 IP 的多项发现合并为一条告警，减少界面噪音
    findings = statistical_findings(records, thresholds)
    findings_by_ip: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        findings_by_ip[finding["ip"]].append(finding)
        stat_type_counts[finding["type"]] += 1

    for ip, items in findings_by_ip.items():
        items.sort(key=lambda item: item["time"])
        highest = min(items, key=lambda item: LEVEL_WEIGHT[item["level"]])
        categories = sorted({STAT_RULES[item["type"]]["category"] for item in items})
        for category in categories:
            category_counts[category] += 1
        level_counts[highest["level"]] += 1
        ip_levels[ip][highest["level"]] += 1

        pseudo_rules = []
        seen_ids = set()
        for item in items:
            meta = STAT_RULES[item["type"]]
            if meta["id"] in seen_ids:
                continue
            seen_ids.add(meta["id"])
            pseudo_rules.append(dict(meta))

        top_route = ip_routes[ip].most_common(1)[0][0] if ip_routes[ip] else "-"
        top_method = ip_methods[ip].most_common(1)[0][0] if ip_methods[ip] else "-"
        top_status = ip_status[ip].most_common(1)[0][0] if ip_status[ip] else 0

        events.append(
            {
                "dt": items[0]["time"],
                "time": items[0]["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "level": highest["level"],
                "source": "statistic",
                "ip": ip,
                "real_ip": ip,
                "method": top_method,
                "path": top_route,
                "route": top_route,
                "status": top_status,
                "ua": ip_ua.get(ip, "-"),
                "categories": categories,
                "rules": pseudo_rules,
                "detail": "；".join(item["detail"] for item in items),
                "evidence": [
                    {
                        "type": item["type"],
                        "detail": item["detail"],
                        "evidence": item["evidence"],
                    }
                    for item in items
                ],
            }
        )

    total_events = len(events)
    # 同一等级内优先展示“统计检测”的聚合结论，再按时间倒序展示单条规则命中
    events.sort(
        key=lambda item: (
            LEVEL_WEIGHT[item["level"]],
            0 if item["source"] == "statistic" else 1,
            -item["dt"].timestamp(),
        )
    )
    stored_events = events[:max_events]
    timeline = _build_event_timeline(stored_events)
    for index, event in enumerate(stored_events, 1):
        event["id"] = index
        event["ts"] = event["dt"].timestamp()
        event.pop("dt", None)

    by_rule: list[dict] = []
    rule_index = {rule.id: rule for rule in engine.rules}
    for rule_id, count in rule_hits.items():
        rule = rule_index[rule_id]
        by_rule.append(
            {
                "id": rule.id,
                "name": rule.name,
                "level": rule.level,
                "category": rule.category,
                "count": count,
                "source": "rule",
            }
        )
    for finding_type, count in stat_type_counts.items():
        meta = STAT_RULES[finding_type]
        by_rule.append(
            {
                "id": meta["id"],
                "name": meta["name"],
                "level": meta["level"],
                "category": meta["category"],
                "count": count,
                "source": "statistic",
            }
        )
    by_rule.sort(key=lambda item: (-item["count"], LEVEL_WEIGHT[item["level"]]))

    by_category = [
        {
            "category": category,
            "name": engine.category_label(category),
            "count": count,
        }
        for category, count in category_counts.most_common()
    ]

    top_ips = [
        {
            "ip": ip,
            "count": sum(levels.values()),
            "high": levels.get("high", 0),
            "medium": levels.get("medium", 0),
            "low": levels.get("low", 0),
        }
        for ip, levels in sorted(
            ip_levels.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])
        )[:10]
    ]

    statistical_summary = [
        {
            "type": finding_type,
            "id": STAT_RULES[finding_type]["id"],
            "name": STAT_RULES[finding_type]["name"],
            "level": STAT_RULES[finding_type]["level"],
            "count": count,
        }
        for finding_type, count in stat_type_counts.most_common()
    ]

    return {
        "events": stored_events,
        "summary": {
            "total": total_events,
            "stored": len(stored_events),
            "truncated": total_events > len(stored_events),
            "high": level_counts.get("high", 0),
            "medium": level_counts.get("medium", 0),
            "low": level_counts.get("low", 0),
            "by_category": by_category,
            "by_rule": by_rule,
            "top_ips": top_ips,
            "statistical": statistical_summary,
            "timeline": timeline,
            "levels": LEVEL_LABELS,
            "rules_version": engine.version,
            "rule_count": len(engine.rules),
        },
    }


def _build_event_timeline(events: list[dict]) -> list[dict]:
    """异常告警的时间分布（按分钟/小时/天）。"""
    if not events:
        return []
    moments = [event["dt"] for event in events]
    start, end = min(moments), max(moments)
    span = (end - start).total_seconds()
    if span <= 3 * 3600:
        bucket, step_seconds, label_format = "minute", 60, "%m-%d %H:%M"
    elif span <= 4 * 86400:
        bucket, step_seconds, label_format = "hour", 3600, "%m-%d %H:00"
    else:
        bucket, step_seconds, label_format = "day", 86400, "%m-%d"

    def key(moment: datetime) -> datetime:
        if bucket == "minute":
            return moment.replace(second=0, microsecond=0)
        if bucket == "hour":
            return moment.replace(minute=0, second=0, microsecond=0)
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)

    counts: dict[datetime, Counter[str]] = defaultdict(Counter)
    for event in events:
        counts[key(event["dt"])][event["level"]] += 1

    points: list[dict] = []
    cursor = key(start)
    last = key(end)
    step = step_seconds
    while cursor <= last:
        counter = counts.get(cursor, Counter())
        points.append(
            {
                "time": cursor.strftime(label_format),
                "high": counter.get("high", 0),
                "medium": counter.get("medium", 0),
                "low": counter.get("low", 0),
                "total": sum(counter.values()),
            }
        )
        cursor = cursor + timedelta(seconds=step)
    return points
