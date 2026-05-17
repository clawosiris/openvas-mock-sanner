#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


REPO_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATIONS_DIR = REPO_ROOT / "implementations"
RESULTS_DIR = REPO_ROOT / "results"
DEFAULT_REVIEWS_DIR = REPO_ROOT / "reviews"
MODEL_TIMES_PATH = RESULTS_DIR / "model-generation-times.json"

REVIEW_WEIGHTS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
    "nit": 0.25,
}


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


def implementation_dirs(selected: str | None = None) -> list[Path]:
    if selected:
        candidate = IMPLEMENTATIONS_DIR / selected
        return [candidate] if candidate.exists() else []
    return sorted(
        path for path in IMPLEMENTATIONS_DIR.iterdir()
        if path.is_dir() and (path / "benchmark.json").exists()
    )


def run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def latest_benchmark_summary(implementation: str) -> dict[str, Any] | None:
    paths = sorted((RESULTS_DIR / implementation).glob("*/summary.json"))
    if not paths:
        return None
    latest = paths[-1]
    data = json.loads(latest.read_text(encoding="utf-8"))
    data["summary_path"] = str(latest.relative_to(REPO_ROOT))
    return data


def count_rust_loc(implementation_dir: Path) -> tuple[int, int]:
    total_loc = 0
    longest_file_lines = 0
    for rust_file in implementation_dir.glob("src/**/*.rs"):
        lines = rust_file.read_text(encoding="utf-8").splitlines()
        longest_file_lines = max(longest_file_lines, len(lines))
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
                total_loc += 1
    return total_loc, longest_file_lines


def dependency_count(implementation_dir: Path) -> int:
    lock_path = implementation_dir / "Cargo.lock"
    if not lock_path.exists() or tomllib is None:
        return 0
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("package", [])
    root_name = None
    cargo_toml = implementation_dir / "Cargo.toml"
    if cargo_toml.exists():
        cargo_data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        root_name = cargo_data.get("package", {}).get("name")
    count = 0
    for package in packages:
        if package.get("name") != root_name:
            count += 1
    return count


def maintainability_score(rust_loc: int, longest_file_lines: int, dependency_total: int) -> tuple[float, list[str]]:
    score = 10.0
    notes: list[str] = []
    if rust_loc > 800:
        score -= 4
        notes.append(f"high Rust LOC: {rust_loc}")
    elif rust_loc > 400:
        score -= 2
        notes.append(f"moderate Rust LOC: {rust_loc}")

    if longest_file_lines > 500:
        score -= 4
        notes.append(f"very large Rust file: {longest_file_lines} lines")
    elif longest_file_lines > 300:
        score -= 2
        notes.append(f"large Rust file: {longest_file_lines} lines")

    if dependency_total > 20:
        score -= 4
        notes.append(f"high dependency count: {dependency_total}")
    elif dependency_total > 10:
        score -= 2
        notes.append(f"moderate dependency count: {dependency_total}")

    return max(score, 0.0), notes


def load_review_findings(reviews_root: Path, implementation: str) -> dict[str, Any] | None:
    review_path = reviews_root / f"{implementation}.json"
    if not review_path.exists():
        return None
    data = json.loads(review_path.read_text(encoding="utf-8"))
    data["review_path"] = str(review_path.relative_to(REPO_ROOT))
    return data


def reviewer_score(review_data: dict[str, Any] | None) -> tuple[float | None, list[dict[str, Any]], Counter[str]]:
    if not review_data:
        return None, [], Counter()
    findings = review_data.get("findings", [])
    penalty = 0.0
    severity_counts: Counter[str] = Counter()
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        confirmed = bool(finding.get("confirmed", False) or finding.get("reproducible", False))
        if not confirmed and finding.get("status") not in {"confirmed", "reproduced"}:
            continue
        weight = REVIEW_WEIGHTS.get(severity, 1.0)
        penalty += weight
        severity_counts[severity] += 1
        normalized.append(finding)
    return max(20.0 - penalty, 0.0), normalized, severity_counts


def score_implementation(implementation_dir: Path, reviews_root: Path, generation_times: dict[str, dict[str, Any]]) -> dict[str, Any]:
    implementation = implementation_dir.name
    benchmark = latest_benchmark_summary(implementation)
    correctness_score = 50.0 if benchmark and benchmark.get("passed") else 0.0

    cargo_check = run_command(["cargo", "check", "--quiet"], implementation_dir)
    cargo_fmt = run_command(["cargo", "fmt", "--check"], implementation_dir)
    cargo_clippy = run_command(["cargo", "clippy", "--quiet", "--", "-D", "warnings"], implementation_dir)

    static_score = 0.0
    static_score += 5.0 if cargo_check["passed"] else 0.0
    static_score += 5.0 if cargo_fmt["passed"] else 0.0
    static_score += 10.0 if cargo_clippy["passed"] else 0.0

    rust_loc, longest_file_lines = count_rust_loc(implementation_dir)
    deps = dependency_count(implementation_dir)
    maintainability, maintainability_notes = maintainability_score(rust_loc, longest_file_lines, deps)

    review_data = load_review_findings(reviews_root, implementation)
    reviewer, normalized_findings, severity_counts = reviewer_score(review_data)

    total_without_reviewer = correctness_score + static_score + maintainability
    total_with_reviewer = None if reviewer is None else total_without_reviewer + reviewer
    generation = generation_times.get(implementation)

    return {
        "implementation": implementation,
        "benchmark": benchmark,
        "generation_time": generation,
        "scores": {
            "correctness": correctness_score,
            "static_quality": static_score,
            "maintainability": maintainability,
            "reviewer": reviewer,
            "total_without_reviewer": round(total_without_reviewer, 2),
            "total_with_reviewer": None if total_with_reviewer is None else round(total_with_reviewer, 2),
        },
        "static_checks": {
            "cargo_check": cargo_check,
            "cargo_fmt_check": cargo_fmt,
            "cargo_clippy": cargo_clippy,
        },
        "maintainability_metrics": {
            "rust_loc": rust_loc,
            "longest_rust_file_lines": longest_file_lines,
            "dependency_count": deps,
            "notes": maintainability_notes,
        },
        "reviewer_findings": {
            "review_path": None if not review_data else review_data["review_path"],
            "counted_findings": normalized_findings,
            "severity_counts": dict(severity_counts),
        },
    }


def aggregate(selected: str | None, reviews_root: Path) -> dict[str, Any]:
    generation_times = load_generation_times()
    items = [score_implementation(path, reviews_root, generation_times) for path in implementation_dirs(selected)]
    return {
        "reviews_root": str(reviews_root.relative_to(REPO_ROOT)) if reviews_root.is_absolute() and reviews_root.exists() and str(reviews_root).startswith(str(REPO_ROOT)) else str(reviews_root),
        "generation_times_path": str(MODEL_TIMES_PATH.relative_to(REPO_ROOT)) if MODEL_TIMES_PATH.exists() else None,
        "implementations": items,
    }


def render_text(report: dict[str, Any]) -> str:
    lines = [f"Reviews root: {report['reviews_root']}", f"Generation times source: {report.get('generation_times_path') or 'none'}", ""]
    for item in report["implementations"]:
        scores = item["scores"]
        reviewer = "n/a" if scores["reviewer"] is None else scores["reviewer"]
        generation = item.get("generation_time") or {}
        lines.append(
            f"- {item['implementation']}: correctness={scores['correctness']}, static={scores['static_quality']}, maintainability={scores['maintainability']}, reviewer={reviewer}, gen_time={generation.get('duration_human', '-')}, total(no-review)={scores['total_without_reviewer']}, total(with-review)={scores['total_with_reviewer']}"
        )
    return "\n".join(lines) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Quality Scoreboard",
        "",
        f"- Reviews root: `{report['reviews_root']}`",
        f"- Generation times source: `{report['generation_times_path']}`" if report.get("generation_times_path") else "- Generation times source: none",
        "",
        "| Implementation | Correctness | Static | Maintainability | Reviewer | Generation time | Total (no review) | Total (with review) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["implementations"]:
        scores = item["scores"]
        reviewer = "n/a" if scores["reviewer"] is None else scores["reviewer"]
        total_with_reviewer = "n/a" if scores["total_with_reviewer"] is None else scores["total_with_reviewer"]
        generation = item.get("generation_time") or {}
        lines.append(
            f"| {item['implementation']} | {scores['correctness']} | {scores['static_quality']} | {scores['maintainability']} | {reviewer} | {generation.get('duration_human', '-')} | {scores['total_without_reviewer']} | {total_with_reviewer} |"
        )
    for item in report["implementations"]:
        metrics = item["maintainability_metrics"]
        lines.extend([
            "",
            f"## {item['implementation']}",
            "",
            f"- Latest benchmark: `{item['benchmark']['summary_path']}`" if item["benchmark"] else "- Latest benchmark: none",
            f"- Generation time: {item['generation_time']['duration_human']} via `{item['generation_time']['model']}` ({item['generation_time']['status']})" if item.get("generation_time") else "- Generation time: none",
            f"- Rust LOC: {metrics['rust_loc']}",
            f"- Longest Rust file: {metrics['longest_rust_file_lines']} lines",
            f"- Dependency count: {metrics['dependency_count']}",
        ])
        if metrics["notes"]:
            lines.append("- Maintainability notes:")
            for note in metrics["notes"]:
                lines.append(f"  - {note}")
        review_path = item["reviewer_findings"]["review_path"]
        if review_path:
            lines.append(f"- Reviewer findings source: `{review_path}`")
            severity_counts = item["reviewer_findings"]["severity_counts"]
            if severity_counts:
                lines.append("- Counted reviewer findings:")
                for severity, count in sorted(severity_counts.items()):
                    lines.append(f"  - {severity}: {count}")
        else:
            lines.append("- Reviewer findings source: none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Score code quality for benchmark implementations")
    parser.add_argument("--implementation", help="Restrict scoring to one implementation")
    parser.add_argument("--reviews-root", default=str(DEFAULT_REVIEWS_DIR), help="Directory containing optional reviewer finding JSON files")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--write-json", help="Optional output path for JSON report")
    parser.add_argument("--write-markdown", help="Optional output path for Markdown report")
    args = parser.parse_args()

    reviews_root = Path(args.reviews_root)
    report = aggregate(args.implementation, reviews_root)

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
