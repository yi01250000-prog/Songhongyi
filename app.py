"""Flask 应用入口：日志上传、统计接口、异常接口、CSV 导出。

启动方式::

    python app.py

默认单进程内缓存最近一次分析结果：上传时解析一次，之后图表接口只读缓存，
避免“每刷新一次页面就重新解析整份日志”的性能问题。
"""

from __future__ import annotations

import io
import math
import os
import tempfile
import threading
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file

from analyzer import __version__
from analyzer.detector import reload_engine
from analyzer.export import render_events_csv
from analyzer.service import analyze_file, rules_payload

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_LOG = os.path.join(BASE_DIR, "data", "sample_access.log")

#: 允许上传的扩展名（任务书只要求 .log，这里额外兼容 .txt）
ALLOWED_SUFFIXES = {".log", ".txt", ".access", ".out"}

#: 单个文件上限 64 MB，足够百万行日志，也防止误传大文件拖垮进程
MAX_UPLOAD_MB = 64

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    TEMPLATES_AUTO_RELOAD=True,
)
app.json.ensure_ascii = False  # 接口直接返回中文，便于调试


class _DatasetState:
    """保存最近一次分析结果（单进程内存缓存）。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.result: dict | None = None
        self.loaded_at: str | None = None


STATE = _DatasetState()


# ----------------------------------------------------------------------
# 数据集管理
# ----------------------------------------------------------------------
def _analyze_demo() -> dict:
    if not os.path.exists(DEMO_LOG):
        raise FileNotFoundError(
            "演示日志不存在，请先运行：python scripts/generate_sample_log.py"
        )
    result = analyze_file(
        DEMO_LOG, filename=os.path.basename(DEMO_LOG), source="demo"
    )
    with STATE.lock:
        STATE.result = result
        STATE.loaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return result


def _ensure_result() -> dict:
    """首次访问接口时自动加载内置演示日志，打开页面即可看到图表。"""
    with STATE.lock:
        if STATE.result is None:
            return _analyze_demo()
        return STATE.result


def _public_meta(result: dict) -> dict:
    meta = dict(result["meta"])
    meta["loaded_at"] = STATE.loaded_at
    return meta


# ----------------------------------------------------------------------
# 查询参数与过滤
# ----------------------------------------------------------------------
def _int_arg(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def _str_arg(name: str) -> str:
    return (request.args.get(name) or "").strip()


def _event_matches(
    event: dict,
    level: str = "",
    source: str = "",
    category: str = "",
    keyword: str = "",
) -> bool:
    if level and event["level"] != level:
        return False
    if source and event["source"] != source:
        return False
    if category and category not in event.get("categories", []):
        return False
    if keyword:
        haystack = " ".join(
            [
                event.get("ip", ""),
                event.get("real_ip", ""),
                event.get("path", ""),
                event.get("ua", ""),
                event.get("detail", ""),
                " ".join(rule.get("name", "") for rule in event.get("rules", [])),
                " ".join(rule.get("id", "") for rule in event.get("rules", [])),
            ]
        ).lower()
        if keyword.lower() not in haystack:
            return False
    return True


def _filter_events(
    events: list[dict],
    level: str = "",
    source: str = "",
    category: str = "",
    keyword: str = "",
) -> list[dict]:
    return [
        event
        for event in events
        if _event_matches(event, level, source, category, keyword)
    ]


# ----------------------------------------------------------------------
# 页面
# ----------------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html", app_version=__version__)


# ----------------------------------------------------------------------
# 数据接口
# ----------------------------------------------------------------------
@app.get("/api/health")
def health():
    with STATE.lock:
        loaded = STATE.result is not None
    return jsonify(
        {
            "ok": True,
            "status": "ok",
            "version": __version__,
            "dataset_loaded": loaded,
            "demo_available": os.path.exists(DEMO_LOG),
        }
    )


@app.get("/api/stats")
def api_stats():
    result = _ensure_result()
    return jsonify(
        {
            "ok": True,
            "meta": _public_meta(result),
            "stats": result["stats"],
            "rules_version": result["anomalies"]["summary"]["rules_version"],
            "rule_count": result["anomalies"]["summary"]["rule_count"],
        }
    )


@app.get("/api/anomalies")
def api_anomalies():
    result = _ensure_result()
    anomalies = result["anomalies"]
    level = _str_arg("level").lower()
    source = _str_arg("source").lower()
    category = _str_arg("category")
    keyword = _str_arg("keyword")

    filtered = _filter_events(
        anomalies["events"], level=level, source=source, category=category, keyword=keyword
    )
    page_size = _int_arg("page_size", 20, 1, 200)
    total = len(filtered)
    pages = max(1, math.ceil(total / page_size)) if total else 1
    page = min(_int_arg("page", 1), pages)
    start = (page - 1) * page_size
    items = filtered[start : start + page_size]

    return jsonify(
        {
            "ok": True,
            "meta": _public_meta(result),
            "summary": anomalies["summary"],
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "filters": {
                "level": level,
                "source": source,
                "category": category,
                "keyword": keyword,
            },
        }
    )


@app.get("/api/rules")
def api_rules():
    payload = rules_payload()
    return jsonify(
        {
            "ok": True,
            "version": payload["version"],
            "categories": payload["categories"],
            "thresholds": payload["thresholds"],
            "rules": payload["rules"],
            "formats": payload["formats"],
            "rule_count": len(payload["rules"]),
        }
    )


@app.post("/api/rules/reload")
def api_rules_reload():
    """规则热加载：修改 config/rules.json 后无需重启服务。"""
    try:
        engine = reload_engine()
    except (ValueError, OSError) as exc:
        return jsonify({"ok": False, "error": f"规则加载失败：{exc}"}), 400
    return jsonify(
        {
            "ok": True,
            "message": f"规则已重新加载，共 {len(engine.rules)} 条",
            "rule_count": len(engine.rules),
            "version": engine.version,
        }
    )


@app.post("/api/demo")
def api_demo():
    try:
        result = _analyze_demo()
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    return jsonify({"ok": True, "meta": _public_meta(result)})


@app.post("/api/upload")
def api_upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"ok": False, "error": "请选择要上传的日志文件"}), 400

    filename = os.path.basename(upload.filename).strip()
    suffix = os.path.splitext(filename)[1].lower()
    if suffix not in ALLOWED_SUFFIXES:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"不支持的文件类型 {suffix or '(无扩展名)'}，请上传 .log 或 .txt 文件",
                }
            ),
            400,
        )

    fd, tmp_path = tempfile.mkstemp(prefix="upload_", suffix=".log")
    os.close(fd)
    try:
        upload.save(tmp_path)
        if os.path.getsize(tmp_path) == 0:
            return jsonify({"ok": False, "error": "上传的文件为空"}), 400

        result = analyze_file(tmp_path, filename=filename, source="upload")
        if result["meta"]["parsed_lines"] == 0:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "未能解析出有效日志行，请确认文件是 Nginx/Apache combined 格式",
                        "meta": result["meta"],
                    }
                ),
                422,
            )

        with STATE.lock:
            STATE.result = result
            STATE.loaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return jsonify({"ok": True, "meta": _public_meta(result)})
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


# ----------------------------------------------------------------------
# CSV 导出
# ----------------------------------------------------------------------
@app.get("/api/anomalies/export")
def export_anomalies():
    result = _ensure_result()
    filtered = _filter_events(
        result["anomalies"]["events"],
        level=_str_arg("level").lower(),
        source=_str_arg("source").lower(),
        category=_str_arg("category"),
        keyword=_str_arg("keyword"),
    )

    data = render_events_csv(filtered)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO(data),
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=f"anomaly_report_{stamp}.csv",
    )


# ----------------------------------------------------------------------
# 错误处理
# ----------------------------------------------------------------------
@app.errorhandler(413)
def handle_too_large(_error):
    return (
        jsonify(
            {
                "ok": False,
                "error": f"文件超过 {MAX_UPLOAD_MB} MB 限制，请先拆分日志",
            }
        ),
        413,
    )


@app.errorhandler(FileNotFoundError)
def handle_missing_file(error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": str(error)}), 404
    return "<h1>404</h1><p>文件不存在，<a href=\"/\">返回首页</a></p>", 404


@app.errorhandler(404)
def handle_not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "接口不存在"}), 404
    return "<h1>404</h1><p>页面不存在，<a href=\"/\">返回首页</a></p>", 404


@app.errorhandler(500)
def handle_server_error(_error):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "服务器内部错误，请查看控制台日志"}), 500
    return "<h1>500</h1><p>服务器内部错误，<a href=\"/\">返回首页</a></p>", 500


@app.after_request
def add_no_cache_headers(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def main() -> None:
    port = int(os.environ.get("PORT", "5000"))
    if os.path.exists(DEMO_LOG):
        try:
            _ensure_result()
            print(f"[启动] 演示日志已加载：{DEMO_LOG}")
        except Exception as exc:  # 演示日志损坏也不应阻止服务启动
            print(f"[警告] 演示日志预加载失败：{exc}")

    print("=" * 64)
    print(" 网站访问日志可视化分析工具")
    print(f" 访问地址：http://127.0.0.1:{port}")
    print(f" 规则文件：{os.path.join(BASE_DIR, 'config', 'rules.json')}")
    print("=" * 64)
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
