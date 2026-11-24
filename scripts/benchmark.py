"""性能基准测试：验证“1 万行不卡顿”，并给出 10 万行日志的扩展性数据。

用法::

    python scripts/benchmark.py
    python scripts/benchmark.py --repeat 5 --synthetic 100000
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analyzer.detector import detect_anomalies  # noqa: E402
from analyzer.parser import LogParser  # noqa: E402
from analyzer.service import analyze_file  # noqa: E402
from analyzer.stats import compute_stats  # noqa: E402
from scripts.generate_sample_log import generate  # noqa: E402

DEFAULT_LOG = os.path.join(BASE_DIR, "data", "sample_access.log")


def measure_demo(path: str, repeat: int) -> dict:
    parser = LogParser()
    parse_times: list[float] = []
    stats_times: list[float] = []
    detect_times: list[float] = []
    full_times: list[float] = []
    records = []

    for _ in range(repeat):
        started = time.perf_counter()
        result = parser.parse_file(path)
        parse_times.append(time.perf_counter() - started)
        records = result.records

        started = time.perf_counter()
        compute_stats(records)
        stats_times.append(time.perf_counter() - started)

        started = time.perf_counter()
        detect_anomalies(records)
        detect_times.append(time.perf_counter() - started)

        started = time.perf_counter()
        analyze_file(path)
        full_times.append(time.perf_counter() - started)

    return {
        "lines": len(records),
        "parse_median_ms": round(statistics.median(parse_times) * 1000, 1),
        "stats_median_ms": round(statistics.median(stats_times) * 1000, 1),
        "detect_median_ms": round(statistics.median(detect_times) * 1000, 1),
        "full_median_ms": round(statistics.median(full_times) * 1000, 1),
        "full_best_ms": round(min(full_times) * 1000, 1),
        "lines_per_second": int(len(records) / statistics.median(full_times)),
    }


def measure_synthetic(count: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="wla_bench_") as tmp:
        path = os.path.join(tmp, "access_100k.log")
        started = time.perf_counter()
        generate(path, normal_count=max(1000, count - 731))
        generate_ms = (time.perf_counter() - started) * 1000

        result = analyze_file(path)
        meta = result["meta"]
        return {
            "lines": meta["parsed_lines"],
            "file_mb": round(meta["size_bytes"] / 1024 / 1024, 2),
            "generate_ms": round(generate_ms, 1),
            "parse_ms": meta["parse_ms"],
            "full_ms": meta["analyze_ms"],
            "lines_per_second": int(meta["parsed_lines"] / (meta["analyze_ms"] / 1000)),
            "events": result["anomalies"]["summary"]["total"],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="日志分析性能基准")
    parser.add_argument("--log", default=DEFAULT_LOG, help="演示日志路径")
    parser.add_argument("--repeat", type=int, default=3, help="演示日志重复次数")
    parser.add_argument("--synthetic", type=int, default=100000, help="扩展性测试行数")
    parser.add_argument("--json", help="把结果写入 JSON 文件")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"日志不存在：{args.log}，请先运行 scripts/generate_sample_log.py")
        raise SystemExit(1)

    demo = measure_demo(args.log, args.repeat)
    print("=" * 64)
    print(f"演示日志：{demo['lines']} 行")
    print(f"  解析      {demo['parse_median_ms']:>8.1f} ms")
    print(f"  统计      {demo['stats_median_ms']:>8.1f} ms")
    print(f"  异常检测  {demo['detect_median_ms']:>8.1f} ms")
    print(f"  全流程    {demo['full_median_ms']:>8.1f} ms（最快 {demo['full_best_ms']} ms）")
    print(f"  吞吐      {demo['lines_per_second']:>8} 行/秒")

    synthetic = measure_synthetic(args.synthetic)
    print("-" * 64)
    print(f"合成大日志：{synthetic['lines']} 行 / {synthetic['file_mb']} MB")
    print(f"  解析      {synthetic['parse_ms']:>8.1f} ms")
    print(f"  全流程    {synthetic['full_ms']:>8.1f} ms")
    print(f"  吞吐      {synthetic['lines_per_second']:>8} 行/秒")
    print(f"  告警      {synthetic['events']} 条")
    print("=" * 64)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"demo": demo, "synthetic": synthetic}, fh, ensure_ascii=False, indent=2)
        print(f"结果已写入 {args.json}")


if __name__ == "__main__":
    main()
