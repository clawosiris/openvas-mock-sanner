#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
MODEL_TIMES_PATH = RESULTS_DIR / "model-generation-times.json"


def load_generation_times() -> dict[str, dict[str, Any]]:
    if not MODEL_TIMES_PATH.exists():
        return {}
    payload = json.loads(MODEL_TIMES_PATH.read_text(encoding="utf-8"))
    latest_by_impl: dict[str, dict[str, Any]] = {}
    for run in payload.get("runs", []):
        implementation = run.get("implementation")
        if not implementation:
            continue
        latest_by_impl[str(implementation)] = run
    return latest_by_impl


def load_summary_paths(implementation: str | None = None) -> list[Path]:
    if implementation:
        root = RESULTS_DIR / implementation
        if not root.exists():
            return []
        return sorted(root.glob("*/summary.json"))
    return sorted(RESULTS_DIR.glob("*/*/summary.json"))


def safe_percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def aggregate(paths: list[Path]) -> dict[str, Any]:
    runs_by_impl: dict[str, list[dict[str, Any]]] = defaultdict(list)
    generation_times = load_generation_times()

    for path in paths:
        with path.open("r", encoding="utf-8") as fh:
            summary = json.load(fh)
        implementation = summary.get("implementation") or path.parent.parent.name
        summary["summary_path"] = str(path.relative_to(REPO_ROOT))
        runs_by_impl[implementation].append(summary)

    implementations: list[dict[str, Any]] = []
    total_runs = 0
    total_passed = 0

    for implementation in sorted(runs_by_impl):
        runs = sorted(runs_by_impl[implementation], key=lambda item: item.get("timestamp", ""))
        total_runs += len(runs)
        passed_runs = sum(1 for run in runs if run.get("passed"))
        total_passed += passed_runs
        checks_per_run = [len(run.get("checks", [])) for run in runs]
        passed_checks_per_run = [sum(1 for check in run.get("checks", []) if check.get("passed")) for run in runs]

        failed_check_counter: Counter[str] = Counter()
        failed_check_details: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for run in runs:
            for check in run.get("checks", []):
                if not check.get("passed"):
                    name = check.get("name", "unknown")
                    failed_check_counter[name] += 1
                    failed_check_details[name].append(
                        {
                            "timestamp": run.get("timestamp"),
                            "details": check.get("details", ""),
                        }
                    )

        latest_run = runs[-1] if runs else None
        generation = generation_times.get(implementation)
        implementations.append(
            {
                "implementation": implementation,
                "runs": len(runs),
                "passed_runs": passed_runs,
                "failed_runs": len(runs) - passed_runs,
                "pass_rate": safe_percent(passed_runs, len(runs)),
                "avg_checks": round(sum(checks_per_run) / len(checks_per_run), 2) if checks_per_run else 0.0,
                "avg_passed_checks": round(sum(passed_checks_per_run) / len(passed_checks_per_run), 2) if passed_checks_per_run else 0.0,
                "latest_timestamp": latest_run.get("timestamp") if latest_run else None,
                "latest_passed": latest_run.get("passed") if latest_run else None,
                "latest_summary_path": latest_run.get("summary_path") if latest_run else None,
                "generation_time": generation,
                "failing_checks": [
                    {
                        "name": name,
                        "count": count,
                        "examples": failed_check_details[name][:3],
                    }
                    for name, count in failed_check_counter.most_common()
                ],
            }
        )

    return {
        "results_root": str(RESULTS_DIR.relative_to(REPO_ROOT)),
        "total_implementations": len(implementations),
        "total_runs": total_runs,
        "total_passed_runs": total_passed,
        "overall_pass_rate": safe_percent(total_passed, total_runs),
        "implementations": implementations,
        "generation_times_path": str(MODEL_TIMES_PATH.relative_to(REPO_ROOT)) if MODEL_TIMES_PATH.exists() else None,
    }


def render_markdown(scoreboard: dict[str, Any]) -> str:
    lines = [
        "# Benchmark Scoreboard",
        "",
        f"- Results root: `{scoreboard['results_root']}`",
        f"- Implementations: {scoreboard['total_implementations']}",
        f"- Total runs: {scoreboard['total_runs']}",
        f"- Passed runs: {scoreboard['total_passed_runs']}",
        f"- Overall pass rate: {scoreboard['overall_pass_rate']}%",
        f"- Generation times source: `{scoreboard['generation_times_path']}`" if scoreboard.get("generation_times_path") else "- Generation times source: none",
        "",
        "## Per implementation",
        "",
        "| Implementation | Runs | Passed | Failed | Pass rate | Avg passed checks | Generation time | Latest run | Latest status |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]

    for item in scoreboard["implementations"]:
        generation = item.get("generation_time") or {}
        lines.append(
            "| {implementation} | {runs} | {passed_runs} | {failed_runs} | {pass_rate}% | {avg_passed_checks}/{avg_checks} | {generation_time} | {latest_timestamp} | {latest_passed} |".format(
                implementation=item["implementation"],
                runs=item["runs"],
                passed_runs=item["passed_runs"],
                failed_runs=item["failed_runs"],
                pass_rate=item["pass_rate"],
                avg_passed_checks=item["avg_passed_checks"],
                avg_checks=item["avg_checks"],
                generation_time=generation.get("duration_human", "-"),
                latest_timestamp=item["latest_timestamp"] or "-",
                latest_passed="pass" if item["latest_passed"] else "fail",
            )
        )

    for item in scoreboard["implementations"]:
        lines.extend([
            "",
            f"### {item['implementation']}",
            "",
            f"- Runs: {item['runs']}",
            f"- Pass rate: {item['pass_rate']}%",
            f"- Latest run: `{item['latest_summary_path']}`" if item["latest_summary_path"] else "- Latest run: -",
        ])
        generation = item.get("generation_time")
        if generation:
            lines.append(f"- Generation time: {generation.get('duration_human')} via `{generation.get('model')}` ({generation.get('status')})")
        if item["failing_checks"]:
            lines.append("- Failing checks seen:")
            for check in item["failing_checks"]:
                lines.append(f"  - `{check['name']}`: {check['count']} time(s)")
        else:
            lines.append("- Failing checks seen: none 🎉")

    return "\n".join(lines) + "\n"


def render_text(scoreboard: dict[str, Any]) -> str:
    lines = [
        f"Results root: {scoreboard['results_root']}",
        f"Implementations: {scoreboard['total_implementations']}",
        f"Total runs: {scoreboard['total_runs']}",
        f"Passed runs: {scoreboard['total_passed_runs']}",
        f"Overall pass rate: {scoreboard['overall_pass_rate']}%",
        f"Generation times source: {scoreboard.get('generation_times_path') or 'none'}",
        "",
    ]
    for item in scoreboard["implementations"]:
        generation = item.get("generation_time") or {}
        lines.extend(
            [
                f"- {item['implementation']}: {item['passed_runs']}/{item['runs']} passed ({item['pass_rate']}%), gen_time={generation.get('duration_human', '-')}, latest={item['latest_timestamp']} status={'pass' if item['latest_passed'] else 'fail'}",
            ]
        )
        if item["failing_checks"]:
            lines.append(
                "  failing checks: "
                + ", ".join(f"{check['name']} x{check['count']}" for check in item["failing_checks"])
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate repeated benchmark runs into a scoreboard")
    parser.add_argument("--implementation", help="Restrict aggregation to one implementation")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--write-json", help="Optional output path for JSON scoreboard")
    parser.add_argument("--write-markdown", help="Optional output path for Markdown scoreboard")
    args = parser.parse_args()

    paths = load_summary_paths(args.implementation)
    scoreboard = aggregate(paths)

    if args.write_json:
        json_path = Path(args.write_json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(scoreboard, indent=2) + "\n", encoding="utf-8")

    if args.write_markdown:
        md_path = Path(args.write_markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(scoreboard), encoding="utf-8")

    if args.format == "json":
        print(json.dumps(scoreboard, indent=2))
    elif args.format == "markdown":
        print(render_markdown(scoreboard), end="")
    else:
        print(render_text(scoreboard), end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
