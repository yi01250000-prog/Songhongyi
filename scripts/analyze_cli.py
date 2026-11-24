"""命令行分析工具：不启动 Web 服务也能分析日志并导出告警。

用法::

    python scripts/analyze_cli.py data/sample_access.log
    python scripts/analyze_cli.py data/sample_access.log --csv anomalies.csv
"""

from __future__ import annotations

import argparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analyzer.export import render_events_csv  # noqa: E402
from analyzer.service import analyze_file  # noqa: E402


def print_report(result: dict, top_n: int = 5) -> None:
    meta = result["meta"]
    stats = result["stats"]
    summary = result["anomalies"]["summary"]

    print("=" * 72)
    print(f"文件：{meta['filename']}  大小：{meta['size_label']}  编码：{meta['encoding']}")
    print(
        f"解析：{meta['parsed_lines']}/{meta['total_lines']} 行成功"
        f"（失败 {meta['failed_lines']} 行，成功率 {meta['success_rate']:.1%}）"
        f"，解析 {meta['parse_ms']} ms，全流程 {meta['analyze_ms']} ms"
    )
    print(
        f"统计：请求 {stats['total_requests']} 次，独立 IP {stats['unique_ips']} 个，"
        f"流量 {stats['human_bytes']}，时间范围 {stats['first_time']} ~ {stats['last_time']}"
    )
    print(
        f"      错误率 {stats['error_rate']:.2%}，平均 QPS {stats['avg_qps']}，"
        f"峰值 QPS {stats['peak_qps']}"
    )

    print("-" * 72)
    print(f"Top {top_n} IP：")
    for item in stats["top_ips"][:top_n]:
        print(f"  {item['ip']:<18} {item['count']:>6} 次  {item['percent']:>6.2f}%")
    print(f"Top {top_n} URL：")
    for item in stats["top_urls"][:top_n]:
        print(f"  {item['count']:>6} 次  {item['url']}")

    print("-" * 72)
    print(
        f"异常告警：{summary['total']} 条（高危 {summary['high']}，"
        f"中危 {summary['medium']}，低危 {summary['low']}）"
    )
    print("命中规则 Top：")
    for item in summary["by_rule"][:top_n]:
        print(
            f"  {item['id']:<10} {item['name']:<22} "
            f"{item['count']:>5} 次  等级={item['level']}"
        )
    print("异常 IP Top：")
    for item in summary["top_ips"][:top_n]:
        print(
            f"  {item['ip']:<18} 告警 {item['count']:>4} 条"
            f"（高 {item['high']} / 中 {item['medium']} / 低 {item['low']}）"
        )

    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description="网站访问日志命令行分析工具")
    parser.add_argument("logfile", help="日志文件路径")
    parser.add_argument("--csv", help="把异常明细导出为 CSV 文件")
    parser.add_argument("--top", type=int, default=5, help="展示前 N 名，默认 5")
    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        print(f"文件不存在：{args.logfile}")
        raise SystemExit(1)

    result = analyze_file(args.logfile, filename=os.path.basename(args.logfile))
    print_report(result, top_n=max(1, args.top))

    if args.csv:
        events = result["anomalies"]["events"]
        with open(args.csv, "wb") as fh:
            fh.write(render_events_csv(events))
        print(f"已导出 {len(events)} 条异常明细到 {args.csv}")


if __name__ == "__main__":
    main()
