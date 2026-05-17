#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from score import aggregate as benchmark_aggregate, load_summary_paths
from quality_score import aggregate as quality_aggregate, DEFAULT_REVIEWS_DIR


REPO_ROOT = Path(__file__).resolve().parents[1]


def build_combined(implementation: str | None, reviews_root: Path) -> dict[str, Any]:
    benchmark = benchmark_aggregate(load_summary_paths(implementation))
    quality = quality_aggregate(implementation, reviews_root)

    benchmark_by_impl = {item["implementation"]: item for item in benchmark["implementations"]}
    quality_by_impl = {item["implementation"]: item for item in quality["implementations"]}

    combined_items: list[dict[str, Any]] = []
    for impl in sorted(set(benchmark_by_impl) | set(quality_by_impl)):
        bench = benchmark_by_impl.get(impl, {})
        qual = quality_by_impl.get(impl, {})
        generation = qual.get("generation_time") or bench.get("generation_time")
        scores = qual.get("scores", {})
        combined_items.append(
            {
                "implementation": impl,
                "passed_latest_benchmark": bench.get("latest_passed"),
                "pass_rate": bench.get("pass_rate"),
                "quality_total_without_reviewer": scores.get("total_without_reviewer"),
                "quality_total_with_reviewer": scores.get("total_with_reviewer"),
                "generation_time": generation,
            }
        )

    combined_items.sort(
        key=lambda item: (
            0 if item.get("passed_latest_benchmark") else 1,
            -(item.get("quality_total_with_reviewer") or item.get("quality_total_without_reviewer") or 0),
            (item.get("generation_time") or {}).get("duration_seconds", 10**9),
        )
    )

    return {
        "benchmark_generation_times_path": benchmark.get("generation_times_path"),
        "reviews_root": quality.get("reviews_root"),
        "implementations": combined_items,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Combined Leaderboard",
        "",
        f"- Generation times source: `{report['benchmark_generation_times_path']}`" if report.get("benchmark_generation_times_path") else "- Generation times source: none",
        f"- Reviews root: `{report['reviews_root']}`",
        "",
        "| Rank | Implementation | Latest benchmark | Pass rate | Quality (no review) | Quality (with review) | Generation time |",
        "| ---: | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for index, item in enumerate(report["implementations"], start=1):
        generation = item.get("generation_time") or {}
        quality_with_review = item.get("quality_total_with_reviewer")
        lines.append(
            f"| {index} | {item['implementation']} | {'pass' if item.get('passed_latest_benchmark') else 'fail'} | {item.get('pass_rate', 0)}% | {item.get('quality_total_without_reviewer', 'n/a')} | {quality_with_review if quality_with_review is not None else 'n/a'} | {generation.get('duration_human', '-')} |"
        )
    return "\n".join(lines) + "\n"


def render_text(report: dict[str, Any]) -> str:
    lines = [f"Generation times source: {report.get('benchmark_generation_times_path') or 'none'}", f"Reviews root: {report['reviews_root']}", ""]
    for index, item in enumerate(report["implementations"], start=1):
        generation = item.get("generation_time") or {}
        lines.append(
            f"{index}. {item['implementation']}: latest={'pass' if item.get('passed_latest_benchmark') else 'fail'}, pass_rate={item.get('pass_rate', 0)}%, quality={item.get('quality_total_without_reviewer')}, gen_time={generation.get('duration_human', '-')}"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Combine benchmark, quality, and generation-time views")
    parser.add_argument("--implementation", help="Restrict report to one implementation")
    parser.add_argument("--reviews-root", default=str(DEFAULT_REVIEWS_DIR), help="Directory containing optional reviewer finding JSON files")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--write-json", help="Optional output path for JSON report")
    parser.add_argument("--write-markdown", help="Optional output path for Markdown report")
    args = parser.parse_args()

    report = build_combined(args.implementation, Path(args.reviews_root))
    if args.write_json:
        path = Path(args.write_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.write_markdown:
        path = Path(args.write_markdown)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(report), encoding="utf-8")

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "markdown":
        print(render_markdown(report), end="")
    else:
        print(render_text(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
