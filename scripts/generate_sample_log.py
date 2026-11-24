"""生成演示用 Nginx combined 访问日志（含正常流量与 8 类攻击场景）。

用法::

    python scripts/generate_sample_log.py
    python scripts/generate_sample_log.py --normal 11300 --output data/sample_access.log

生成结果默认约 1.2 万行，覆盖任务书要求的“日志量 ≥ 1 万行”，
并按真实攻击工具的行为构造 SQL 注入、路径遍历、目录扫描、暴力破解、
XSS、命令注入、文件包含、空 UA、5xx 突增等场景，供演示与规则验证使用。
"""

from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUTPUT = os.path.join(BASE_DIR, "data", "sample_access.log")

TZ = timezone(timedelta(hours=8))
DAY = datetime(2026, 9, 7, 0, 0, 0, tzinfo=TZ)

# 攻击场景使用的 IP，正常流量不会使用这些地址
ATTACK_IPS = {
    "203.0.113.99",   # sqlmap 注入
    "198.51.100.23",  # 路径遍历
    "66.102.9.15",    # dirsearch 目录扫描
    "45.148.10.88",   # Hydra 登录爆破
    "185.220.101.7",  # XSS / 命令注入 / 文件包含
    "91.240.118.22",  # 空 UA 后门探测
    "192.0.2.77",     # python-requests 高频抓取
    "198.51.100.88",  # 5xx 突增
}

UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
UA_EDGE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
)
UA_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"
)
UA_IOS = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)
UA_FIREFOX = (
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) "
    "Gecko/20100101 Firefox/129.0"
)
UA_WECHAT = (
    "Mozilla/5.0 (Linux; Android 13; V2227A Build/TP1A.220624.014) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Version/4.0 Chrome/116.0.0.0 Mobile Safari/537.36 "
    "MicroMessenger/8.0.50.2701(0x2800323B) WeChat/arm64 Weixin NetType/WIFI"
)
UA_BAIDU = (
    "Mozilla/5.0 (compatible; Baiduspider/2.0; "
    "+http://www.baidu.com/search/spider.html)"
)
UA_GOOGLE = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)"
)

NORMAL_UA_POOL = [
    (UA_CHROME, 34),
    (UA_ANDROID, 20),
    (UA_IOS, 15),
    (UA_EDGE, 10),
    (UA_WECHAT, 10),
    (UA_FIREFOX, 4),
    (UA_BAIDU, 3),
    (UA_GOOGLE, 2),
]

# (路径, 权重, 典型字节数)
NORMAL_PATHS = [
    ("/", 16, 18500),
    ("/index.html", 10, 18600),
    ("/news", 9, 23000),
    ("/news/2026/09/07/season-opening", 5, 24500),
    ("/product/list", 8, 21000),
    ("/product/detail?id=1001", 7, 19500),
    ("/product/detail?id=1002", 5, 19800),
    ("/about", 4, 12800),
    ("/contact", 3, 9600),
    ("/search?q=web", 6, 14300),
    ("/search?q=python", 3, 14800),
    ("/api/data", 7, 820),
    ("/api/notice", 4, 1560),
    ("/static/css/app.css", 8, 24500),
    ("/static/js/app.js", 8, 96500),
    ("/images/banner.png", 6, 182000),
    ("/images/logo.svg", 4, 4200),
    ("/download/report.pdf", 2, 1240000),
    ("/login", 5, 7800),
    ("/register", 2, 8100),
    ("/blog/nginx-log-format", 4, 21200),
    ("/blog/echarts-dashboard", 3, 23800),
    ("/favicon.ico", 3, 1150),
]

STATIC_SUFFIXES = (".css", ".js", ".png", ".svg", ".ico", ".pdf")

SEARCH_TERMS = [
    "日志分析", "web", "python", "flask", "echarts", "nginx",
    "安全", "报表", "可视化", "dashboard",
]

# dirsearch 字典（目录扫描）
SCAN_WORDS = [
    "admin", "administrator", "login", "logout", "dashboard", "manage",
    "manager", "backup", "backups", "bak", "db", "database", "sql",
    "config", "conf", "setup", "install", "test", "tests", "dev", "debug",
    "api", "api/v1", "api/v2", "docs", "doc", "swagger", "phpinfo",
    "phpmyadmin", "pma", "mysql", "wp-admin", "wp-login", "wp-config",
    "uploads", "upload", "files", "file", "download", "downloads",
    "old", "new", "tmp", "temp", "cache", "logs", "log", "private",
    "secret", "internal", "portal", "webmail", "cpanel", "server-status",
    "robots.txt", "sitemap.xml", ".git", ".svn", ".hg", ".env", ".DS_Store",
    "console", "actuator", "metrics", "health", "status", "graphql",
]

SCAN_FILES = [
    ".git/config", ".git/HEAD", ".git/index", ".svn/entries", ".env",
    ".env.local", ".env.production", ".DS_Store", ".htaccess", ".htpasswd",
    "phpinfo.php", "config.php", "config.php.bak", "wp-config.php",
    "wp-config.php.bak", "database.sql", "db.sql", "backup.zip", "backup.tar.gz",
    "www.zip", "web.rar", "index.php.bak", "app.py", "requirements.txt",
    "docker-compose.yml", "Dockerfile", ".aws/credentials", "id_rsa",
    "server-status", "actuator/env", "actuator/health", "console",
    "phpmyadmin/index.php", "wp-login.php", "xmlrpc.php", "readme.html",
]


def build_line(
    ip: str,
    moment: datetime,
    method: str,
    path: str,
    status: int,
    size: int,
    referer: str = "-",
    ua: str = "-",
) -> str:
    """拼一行 combined 格式日志。"""
    timestamp = moment.strftime("%d/%b/%Y:%H:%M:%S %z")
    request = f"{method} {path} HTTP/1.1"
    return (
        f'{ip} - - [{timestamp}] "{request}" {status} {size} '
        f'"{referer}" "{ua}"'
    )


def weighted_choice(pairs):
    """从 [(value, weight), ...] 中按权重取一个值。"""
    values = [item[0] for item in pairs]
    weights = [item[1] for item in pairs]
    return random.choices(values, weights=weights, k=1)[0]


def make_normal_ips(count: int = 150) -> tuple[list[str], list[float]]:
    """生成正常访客 IP 池，排除攻击 IP，权重近似 Zipf 分布。"""
    pools = [
        [f"203.0.113.{i}" for i in range(1, 255)],
        [f"198.51.100.{i}" for i in range(1, 255)],
        [f"192.0.2.{i}" for i in range(1, 255)],
        [f"175.24.{i}.{j}" for i in range(1, 40) for j in range(1, 40)],
        [f"116.62.{i}.{j}" for i in range(1, 30) for j in range(1, 30)],
        [f"39.156.{i}.{j}" for i in range(1, 30) for j in range(1, 30)],
    ]
    candidates: list[str] = []
    for pool in pools:
        candidates.extend(pool)
    candidates = [ip for ip in candidates if ip not in ATTACK_IPS]
    random.shuffle(candidates)
    selected = candidates[:count]
    # 幂指数 0.55 的“长尾”分布：头部 IP 约占 5%，比极端 Zipf 更接近真实站点
    weights = [1.0 / ((index + 1) ** 0.55) for index in range(len(selected))]
    return selected, weights


def generate(path: str = DEFAULT_OUTPUT, normal_count: int = 11300, seed: int = 20260907) -> dict:
    """生成日志并写入 path，返回各场景行数统计。"""
    random.seed(seed)
    entries: list[tuple[datetime, int, str]] = []
    counters = {"normal": 0}

    def add(
        moment: datetime,
        ip: str,
        method: str,
        target: str,
        status: int,
        size: int,
        ua: str,
        referer: str = "-",
    ) -> None:
        entries.append(
            (moment, len(entries), build_line(ip, moment, method, target, status, size, referer, ua))
        )

    # ------------------------------------------------------------------
    # 1. 正常流量：按 24 小时的“人体作息”分布
    # ------------------------------------------------------------------
    ips, ip_weights = make_normal_ips(150)
    hourly_weights = [
        0.16, 0.11, 0.08, 0.06, 0.06, 0.09, 0.22, 0.42,
        0.72, 1.00, 1.10, 1.02, 0.78, 0.92, 1.12, 1.16,
        1.04, 0.90, 0.82, 0.88, 0.98, 0.92, 0.62, 0.36,
    ]
    total_weight = sum(hourly_weights)
    hour_counts = [int(normal_count * weight / total_weight) for weight in hourly_weights]
    for index in range(normal_count - sum(hour_counts)):
        hour_counts[index % 24] += 1

    for hour, count in enumerate(hour_counts):
        for _ in range(count):
            second = random.randint(0, 3599)
            moment = DAY + timedelta(hours=hour, seconds=second)
            ip = random.choices(ips, weights=ip_weights, k=1)[0]
            ua = weighted_choice(NORMAL_UA_POOL)
            is_bot = ua in (UA_BAIDU, UA_GOOGLE)

            url_path, _, size = weighted_choice(
                [(item, item[1]) for item in NORMAL_PATHS]
            )
            if url_path.startswith("/search?q=") and random.random() < 0.7:
                url_path = f"/search?q={random.choice(SEARCH_TERMS)}"
            if url_path.startswith("/product/detail"):
                url_path = f"/product/detail?id={random.randint(1001, 1100)}"

            method = "GET"
            status = 200
            if random.random() < 0.06 and url_path in ("/login", "/api/data"):
                method = "POST"
                status = random.choices([200, 302, 401], weights=[80, 15, 5], k=1)[0]
            elif random.random() < 0.035:
                method = "HEAD"
            elif random.random() < 0.01:
                method = "OPTIONS"
                status = 204

            if status == 200:
                if url_path.endswith(STATIC_SUFFIXES) and random.random() < 0.28:
                    status = 304
                elif random.random() < 0.02:
                    status = random.choices([301, 302], weights=[6, 4], k=1)[0]
                elif random.random() < 0.004:
                    status = 500
                elif random.random() < 0.015:
                    status = 404
            if status == 304:
                size = 0
            elif status == 404:
                url_path = (
                    f"/{random.choice(['old-page', 'temp', 'undefined', 'archive'])}"
                    f"/{random.randint(1, 99)}"
                )
                size = random.randint(140, 260)
            else:
                size = max(0, int(size * random.uniform(0.72, 1.28)))

            referer = "-"
            if random.random() < 0.38:
                referer = random.choice(
                    [
                        "https://www.example.com/",
                        "https://www.example.com/news",
                        "https://www.example.com/product/list",
                        "https://www.baidu.com/s?wd=日志分析",
                        "https://www.google.com/",
                    ]
                )
            if is_bot:
                referer = "-"

            add(moment, ip, method, url_path, status, size, ua, referer)
            counters["normal"] += 1

    # ------------------------------------------------------------------
    # 2. sqlmap：SQL 注入（含编码 / 注释 / 盲注变体）
    # ------------------------------------------------------------------
    sqli_paths = [
        "/news.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/news.php?id=2%27%20UNION%20SELECT%20NULL,NULL--",
        "/search?q=UnIoN/**/SeLeCt",
        "/login?u=admin%27%20OR%20%271%27=%271",
        "/item.php?id=1%20AND%20SLEEP(5)",
        "/product.php?id=1%20AND%20(SELECT%201%20FROM%20(SELECT%20SLEEP(5))x)",
        "/news.php?id=1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables",
        "/news.php?id=1%27%20AND%20BENCHMARK(5000000,MD5(1))--",
        "/catalog?category=1%20OR%201=1",
        "/user.php?id=1%20UNION%20SELECT%20load_file(%27/etc/passwd%27)",
        "/news.php?id=1%27%20UNION%20SELECT%20NULL--",
        "/login?u=admin%27--",
        "/news.php?id=5%27%20OR%20%271%27=%271--",
        "/api/v1/user?id=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL--",
    ]
    for index, target in enumerate(sqli_paths):
        moment = DAY + timedelta(hours=3, minutes=10, seconds=index * 47)
        status = 200 if index % 4 != 3 else 500
        size = random.randint(1200, 5200) if status == 200 else random.randint(180, 420)
        add(moment, "203.0.113.99", "GET", target, status, size, "sqlmap/1.7.2#stable")
        counters["sql_injection"] = counters.get("sql_injection", 0) + 1

    # ------------------------------------------------------------------
    # 3. 路径遍历：../../etc/passwd 及编码变体
    # ------------------------------------------------------------------
    traversal_paths = [
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2f..%2f..%2fetc%2fpasswd",
        "/download?file=..%5c..%5cwindows%5cwin.ini",
        "/download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "/download?file=....//....//etc/passwd",
        "/include?page=../../../../proc/self/environ",
        "/static/../../../../etc/passwd",
        "/download?file=..%252f..%252fetc%252fpasswd",
    ]
    for index, target in enumerate(traversal_paths):
        moment = DAY + timedelta(hours=3, minutes=20, seconds=index * 13)
        add(
            moment,
            "198.51.100.23",
            "GET",
            target,
            404,
            random.randint(150, 210),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        )
        counters["path_traversal"] = counters.get("path_traversal", 0) + 1

    # ------------------------------------------------------------------
    # 4. dirsearch：目录扫描（同一分钟内约 240 个 404）
    # ------------------------------------------------------------------
    scan_targets: list[str] = []
    for word in SCAN_WORDS:
        scan_targets.append(f"/{word}")
        scan_targets.append(f"/{word}/")
    for name in SCAN_FILES:
        scan_targets.append(f"/{name}")
    scan_targets.extend(
        f"/{word}.{ext}"
        for word in ("backup", "database", "site", "www", "wwwroot")
        for ext in ("zip", "rar", "tar.gz", "bak", "old", "sql")
    )
    scan_targets.extend(
        f"/admin/{index}" for index in range(1, 31)
    )
    scan_targets = list(dict.fromkeys(scan_targets))
    random.shuffle(scan_targets)
    scan_targets = scan_targets[:240]
    for index, target in enumerate(scan_targets):
        # 240 个请求集中在 60 秒内，平均每秒 4 个
        moment = DAY + timedelta(hours=3, minutes=31, seconds=index // 4)
        add(
            moment,
            "66.102.9.15",
            "GET",
            target,
            404,
            random.randint(140, 162),
            "dirsearch/0.4.3",
        )
        counters["directory_scan"] = counters.get("directory_scan", 0) + 1

    # ------------------------------------------------------------------
    # 5. Hydra：登录接口暴力破解（41 次 401 后出现 200）
    # ------------------------------------------------------------------
    for index in range(41):
        moment = DAY + timedelta(hours=4, minutes=5, seconds=index * 9)
        add(
            moment,
            "45.148.10.88",
            "POST",
            "/admin/login",
            401,
            189,
            "Hydra/9.4",
        )
        counters["bruteforce"] = counters.get("bruteforce", 0) + 1
    add(
        DAY + timedelta(hours=4, minutes=11, seconds=57),
        "45.148.10.88",
        "POST",
        "/admin/login",
        200,
        1204,
        "Hydra/9.4",
    )
    counters["bruteforce"] += 1

    # ------------------------------------------------------------------
    # 6. 综合 Web 攻击：XSS、命令注入、文件包含、WebShell 探测
    # ------------------------------------------------------------------
    mixed_attacks = [
        ("/comment?text=<script>alert(1)</script>", 200, 1500),
        ("/search?q=<img%20src=x%20onerror=alert(1)>", 200, 1420),
        ("/redirect?url=javascript:alert(document.cookie)", 302, 0),
        ("/ping?host=127.0.0.1;cat%20/etc/passwd", 500, 320),
        ("/ping?host=127.0.0.1|whoami", 500, 280),
        ("/util?file=php://filter/convert.base64-encode/resource=index.php", 200, 2600),
        ("/index.php?page=php://input", 200, 2180),
        ("/upload.php", 404, 168),
        ("/shell.php?cmd=id", 404, 166),
        ("/admin/backup.zip", 404, 158),
        ("/api/exec?cmd=%60id%60", 500, 300),
        ("/download?file=../../../../etc/passwd%00.jpg", 400, 180),
    ]
    for index, (target, status, size) in enumerate(mixed_attacks):
        moment = DAY + timedelta(hours=2, minutes=40, seconds=index * 37)
        add(
            moment,
            "185.220.101.7",
            "GET",
            target,
            status,
            size,
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        )
        counters["mixed_web_attack"] = counters.get("mixed_web_attack", 0) + 1

    # ------------------------------------------------------------------
    # 7. 空 UA 的后门 / 备份文件探测
    # ------------------------------------------------------------------
    for index in range(25):
        target = random.choice(
            [
                f"/backup/{random.randint(1, 99)}.zip",
                f"/db/dump_{random.randint(2000, 2026)}.sql",
                "/.env",
                "/admin/config.php.bak",
                "/server-status",
                "/actuator/env",
            ]
        )
        moment = DAY + timedelta(hours=1, minutes=10, seconds=index * 21)
        add(
            moment,
            "91.240.118.22",
            "GET",
            target,
            404,
            random.randint(140, 190),
            "",
        )
        counters["empty_ua_scan"] = counters.get("empty_ua_scan", 0) + 1

    # ------------------------------------------------------------------
    # 8. python-requests 高频抓取（每分钟约 60 次）
    # ------------------------------------------------------------------
    for index in range(300):
        moment = DAY + timedelta(hours=2, minutes=index // 60, seconds=index % 60)
        target = f"/search?q={random.choice(SEARCH_TERMS)}&page={random.randint(1, 9)}"
        add(
            moment,
            "192.0.2.77",
            "GET",
            target,
            200,
            random.randint(14000, 16000),
            "python-requests/2.31.0",
        )
        counters["high_frequency"] = counters.get("high_frequency", 0) + 1

    # ------------------------------------------------------------------
    # 9. 支付接口 5xx 突增（后端故障）
    # ------------------------------------------------------------------
    for index in range(90):
        moment = DAY + timedelta(hours=15, minutes=index // 45, seconds=(index * 2) % 60)
        add(
            moment,
            "198.51.100.88",
            "POST",
            "/api/checkout",
            500,
            random.randint(220, 360),
            UA_CHROME,
            "https://www.example.com/product/list",
        )
        counters["server_error"] = counters.get("server_error", 0) + 1

    # ------------------------------------------------------------------
    # 写入文件（按时间排序，模拟真实日志顺序）
    # ------------------------------------------------------------------
    entries.sort(key=lambda item: (item[0], item[1]))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for _, _, line in entries:
            fh.write(line + "\n")

    counters["total"] = len(entries)
    counters["output"] = os.path.abspath(path)
    return counters


def main() -> None:
    parser = argparse.ArgumentParser(description="生成演示用访问日志")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="输出文件路径")
    parser.add_argument("--normal", type=int, default=11300, help="正常流量行数")
    parser.add_argument("--seed", type=int, default=20260907, help="随机种子")
    args = parser.parse_args()

    stats = generate(args.output, normal_count=args.normal, seed=args.seed)
    print("演示日志生成完成：")
    for key, value in stats.items():
        print(f"  {key:<20} {value}")
    if stats["total"] < 10000:
        print("警告：总行数不足 1 万行，请调大 --normal 参数")


if __name__ == "__main__":
    main()
