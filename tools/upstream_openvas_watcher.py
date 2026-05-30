#!/usr/bin/env python3
"""Watch upstream openvas-scanner changes and file replication issues."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


DEFAULT_UPSTREAM_REPO = "https://github.com/greenbone/openvas-scanner.git"
DEFAULT_GITHUB_REPO = "clawosiris/openvas-mock-sanner"
DEFAULT_STATE_VARIABLE = "OPENVAS_SCANNER_LAST_SEEN"
DEFAULT_PRIMARY_MODEL = "qwen2.5-coder:7b"
DEFAULT_ESCALATION_MODEL = "qwen2.5-coder:14b"
DEFAULT_CONFIDENCE_THRESHOLD = 0.74
STATE_ISSUE_TITLE = "Upstream OpenVAS watcher state"
STATE_ISSUE_MARKER = "<!-- openvas-mock-scanner-upstream-watch-state -->"
LOCAL_GH_BIN = Path("/home/linuxbrew/.linuxbrew/bin/gh")

RELEVANT_PATH_PATTERNS = (
    re.compile(r"(^|/)openvasd(/|$)", re.IGNORECASE),
    re.compile(r"(^|/)ospd-openvas(/|$)", re.IGNORECASE),
    re.compile(r"(^|/)rust/src/(controller|openvasd|scanner|storage|feed|notus|nasl|vt)", re.IGNORECASE),
    re.compile(r"(^|/)(src|misc|nasl|notus|feed|tests?)/", re.IGNORECASE),
    re.compile(r"(^|/)(api|scanner|scan|result|status|preference|capabilit|vt|feed|notus|scap)", re.IGNORECASE),
)

RELEVANT_KEYWORDS = (
    "openvasd",
    "scan",
    "scans",
    "scanner",
    "result",
    "results",
    "status",
    "preference",
    "preferences",
    "capabilities",
    "vts",
    "vt ",
    "feed",
    "notus",
    "scap",
    "nasl",
    "json",
    "http",
    "route",
    "endpoint",
    "delete",
    "start",
    "stop",
    "error",
)


@dataclass(frozen=True)
class ChangedFile:
    status: str
    path: str


@dataclass(frozen=True)
class Classification:
    decision: str
    confidence: float
    summary: str
    reasons: tuple[str, ...]
    suggested_changes: tuple[str, ...]
    model: str
    raw: str


def run(args: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git(repo: Path, *args: str, check: bool = True) -> str:
    completed = run(["git", *args], cwd=repo, check=check)
    return completed.stdout.strip()


def gh_bin() -> str:
    configured = os.environ.get("GH_BIN")
    if configured:
        return configured
    if LOCAL_GH_BIN.exists():
        return str(LOCAL_GH_BIN)
    return "gh"


def gh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run([gh_bin(), *args], check=check)


def ensure_upstream_checkout(repo_url: str, repo_dir: Path, head_ref: str) -> None:
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    refspec = f"+refs/heads/{head_ref}:refs/remotes/origin/{head_ref}"
    if (repo_dir / ".git").exists():
        git(repo_dir, "remote", "set-url", "origin", repo_url)
        git(repo_dir, "fetch", "--prune", "origin", refspec)
    else:
        run(["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(repo_dir)])
        git(repo_dir, "fetch", "--prune", "origin", refspec)
    git(repo_dir, "checkout", "--detach", f"origin/{head_ref}")


def resolve_head(repo: Path, head_ref: str) -> str:
    return git(repo, "rev-parse", f"origin/{head_ref}")


def normalize_base(repo: Path, base_ref: str, head_sha: str) -> str:
    if not base_ref:
        return ""
    resolved = git(repo, "rev-parse", "--verify", base_ref, check=False)
    if not resolved:
        return ""
    base_sha = resolved.splitlines()[0]
    ancestor = run(["git", "merge-base", "--is-ancestor", base_sha, head_sha], cwd=repo, check=False)
    if ancestor.returncode == 0:
        return base_sha
    merge_base = git(repo, "merge-base", base_sha, head_sha, check=False)
    return merge_base or base_sha


def changed_files(repo: Path, base_sha: str, head_sha: str) -> list[ChangedFile]:
    output = git(repo, "diff", "--name-status", base_sha, head_sha)
    files: list[ChangedFile] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        status = parts[0]
        path = parts[-1]
        files.append(ChangedFile(status=status, path=path))
    return files


def is_relevant_path(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith((".md", ".rst", ".txt")) and not any(word in lowered for word in ("api", "scanner", "openvasd")):
        return False
    return any(pattern.search(path) for pattern in RELEVANT_PATH_PATTERNS) or any(keyword in lowered for keyword in RELEVANT_KEYWORDS)


def prefilter(files: list[ChangedFile]) -> list[ChangedFile]:
    return [item for item in files if is_relevant_path(item.path)]


def diff_stat(repo: Path, base_sha: str, head_sha: str) -> str:
    return git(repo, "diff", "--stat", base_sha, head_sha)


def relevant_patch(repo: Path, base_sha: str, head_sha: str, files: list[ChangedFile], max_chars: int) -> str:
    patches: list[str] = []
    for item in files:
        completed = run(["git", "diff", "--unified=40", base_sha, head_sha, "--", item.path], cwd=repo, check=False)
        if completed.stdout:
            patches.append(completed.stdout)
        if sum(len(part) for part in patches) >= max_chars:
            break
    patch = "\n".join(patches)
    if len(patch) > max_chars:
        return patch[:max_chars] + "\n\n[diff truncated]"
    return patch


def build_prompt(base_sha: str, head_sha: str, files: list[ChangedFile], stat: str, patch: str) -> str:
    file_list = "\n".join(f"- {item.status}\t{item.path}" for item in files)
    return textwrap.dedent(
        f"""
        You classify upstream Greenbone openvas-scanner changes for a deterministic mock scanner.

        Goal: decide whether this upstream change alters externally observable behavior that
        clawosiris/openvas-mock-sanner should replicate for gvmd/gvmd-ng compatibility tests.

        Behavior in scope:
        - openvasd HTTP routes, JSON payloads, status transitions, response codes, headers
        - scan creation/start/stop/delete/result paging behavior
        - VT/feed selection, Notus, SCAP, target profile, or diagnostics behavior
        - scanner lifecycle, error semantics, auth/dependency/port timeout behavior

        Ignore:
        - internal-only refactors with no externally visible scanner behavior
        - docs-only changes unless they define API behavior
        - unrelated build, packaging, CI, memory, or style changes

        Return compact JSON only:
        {{
          "decision": "replicate" | "ignore" | "needs-human-review",
          "confidence": 0.0,
          "summary": "one sentence",
          "reasons": ["specific reason"],
          "suggested_changes": ["mock scanner delta if decision is replicate"]
        }}

        Upstream range: {base_sha}..{head_sha}

        Candidate files:
        {file_list}

        Diff stat:
        {stat}

        Relevant patch:
        {patch}
        """
    ).strip()


def ollama_chat(model: str, prompt: str, *, host: str, api_key: str | None, timeout: int) -> str:
    base = host.rstrip("/")
    if base.endswith("/api"):
        url = f"{base}/chat"
    else:
        url = f"{base}/api/chat"
    payload = {
        "model": model,
        "stream": False,
        "options": {"temperature": 0, "top_p": 0.2},
        "messages": [
            {
                "role": "system",
                "content": "You are a strict code-change classifier. Output valid JSON only.",
            },
            {"role": "user", "content": prompt},
        ],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama request failed with HTTP {exc.code}: {body}") from exc
    content = data.get("message", {}).get("content")
    if not isinstance(content, str):
        raise RuntimeError(f"Ollama response did not contain message.content: {data!r}")
    return content


def parse_classification(raw: str, model: str) -> Classification:
    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if not match:
        raise ValueError(f"model {model} did not return JSON: {raw}")
    data = json.loads(match.group(0))
    decision = str(data.get("decision", "")).strip()
    if decision not in {"replicate", "ignore", "needs-human-review"}:
        raise ValueError(f"model {model} returned invalid decision: {decision!r}")
    confidence = float(data.get("confidence", 0.0))
    reasons = tuple(str(item) for item in data.get("reasons", []) if str(item).strip())
    suggested = tuple(str(item) for item in data.get("suggested_changes", []) if str(item).strip())
    return Classification(
        decision=decision,
        confidence=max(0.0, min(1.0, confidence)),
        summary=str(data.get("summary", "")).strip(),
        reasons=reasons,
        suggested_changes=suggested,
        model=model,
        raw=raw,
    )


def classify(prompt: str, args: argparse.Namespace) -> tuple[Classification, Classification | None]:
    host = args.ollama_host or os.environ.get("OLLAMA_CLOUD_BASE_URL") or os.environ.get("OLLAMA_HOST")
    if not host:
        raise RuntimeError("OLLAMA_CLOUD_BASE_URL or OLLAMA_HOST is required for upstream classification")
    api_key = args.ollama_api_key or os.environ.get("OLLAMA_API_KEY") or os.environ.get("OLLAMA_CLOUD_API_KEY")
    primary_raw = ollama_chat(args.primary_model, prompt, host=host, api_key=api_key, timeout=args.timeout)
    primary = parse_classification(primary_raw, args.primary_model)
    if primary.decision == "needs-human-review" or primary.confidence < args.confidence_threshold:
        escalation_raw = ollama_chat(args.escalation_model, prompt, host=host, api_key=api_key, timeout=args.timeout)
        return parse_classification(escalation_raw, args.escalation_model), primary
    return primary, None


def read_state(repo: str, variable: str) -> str:
    try:
        completed = gh("api", f"repos/{repo}/actions/variables/{variable}", "--jq", ".value", check=False)
    except FileNotFoundError:
        completed = None
    if completed and completed.returncode == 0:
        return completed.stdout.strip()
    return read_state_issue(repo)


def write_state(repo: str, variable: str, value: str) -> None:
    exists = gh("api", f"repos/{repo}/actions/variables/{variable}", "--jq", ".name", check=False).returncode == 0
    if exists:
        completed = gh("api", "--method", "PATCH", f"repos/{repo}/actions/variables/{variable}", "-f", f"name={variable}", "-f", f"value={value}", check=False)
    else:
        completed = gh("api", "--method", "POST", f"repos/{repo}/actions/variables", "-f", f"name={variable}", "-f", f"value={value}", check=False)
    if completed.returncode == 0:
        return
    print("Could not update Actions variable state; falling back to issue-backed state.", file=sys.stderr)
    write_state_issue(repo, value)


def state_issue_body(value: str) -> str:
    return textwrap.dedent(
        f"""
        {STATE_ISSUE_MARKER}

        This issue stores automation state for the scheduled upstream OpenVAS
        watcher. It is not an implementation task.

        Last seen upstream commit:

        ```text
        {value}
        ```
        """
    ).strip()


def state_issue(repo: str) -> dict[str, object] | None:
    completed = gh(
        "issue",
        "list",
        "--repo",
        repo,
        "--state",
        "all",
        "--search",
        f"{STATE_ISSUE_TITLE} in:title",
        "--json",
        "number,title,body,state",
        "--limit",
        "10",
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    for issue in json.loads(completed.stdout):
        if issue.get("title") == STATE_ISSUE_TITLE and STATE_ISSUE_MARKER in str(issue.get("body", "")):
            return issue
    return None


def read_state_issue(repo: str) -> str:
    issue = state_issue(repo)
    if not issue:
        return ""
    match = re.search(r"```text\s+([0-9a-f]{40})\s+```", str(issue.get("body", "")), flags=re.IGNORECASE)
    return match.group(1) if match else ""


def write_state_issue(repo: str, value: str) -> None:
    body = state_issue_body(value)
    issue = state_issue(repo)
    if issue:
        gh("issue", "edit", str(issue["number"]), "--repo", repo, "--body", body)
        if issue.get("state") != "CLOSED":
            gh("issue", "close", str(issue["number"]), "--repo", repo, "--comment", "State updated and closed to keep the tracker clear.", check=False)
        return
    created = gh("issue", "create", "--repo", repo, "--title", STATE_ISSUE_TITLE, "--body", body)
    match = re.search(r"/issues/(\d+)", created.stdout)
    if match:
        gh("issue", "close", match.group(1), "--repo", repo, "--comment", "State initialized and closed to keep the tracker clear.", check=False)


def issue_exists(repo: str, base_sha: str, head_sha: str) -> str:
    marker = f"upstream-range:{base_sha[:12]}..{head_sha[:12]}"
    completed = gh(
        "issue",
        "list",
        "--repo",
        repo,
        "--state",
        "open",
        "--search",
        marker,
        "--json",
        "number,url",
        "--limit",
        "1",
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return ""
    issues = json.loads(completed.stdout)
    if not issues:
        return ""
    return str(issues[0]["url"])


def issue_body(base_sha: str, head_sha: str, files: list[ChangedFile], classification: Classification, primary: Classification | None) -> str:
    file_lines = "\n".join(f"- `{item.status}` `{item.path}`" for item in files[:60])
    reasons = "\n".join(f"- {reason}" for reason in classification.reasons) or "- No model reasons returned."
    changes = "\n".join(f"- {change}" for change in classification.suggested_changes) or "- Determine exact mock-scanner delta during implementation."
    primary_note = ""
    if primary:
        primary_note = f"\nPrimary 7B pass: `{primary.decision}` at confidence `{primary.confidence:.2f}`.\n"
    return textwrap.dedent(
        f"""
        The upstream OpenVAS scanner watcher found a change range that may affect behavior this mock scanner should replicate.

        Marker: `upstream-range:{base_sha[:12]}..{head_sha[:12]}`

        Upstream range:
        - Base: `{base_sha}`
        - Head: `{head_sha}`

        Final classifier:
        - Model: `{classification.model}`
        - Decision: `{classification.decision}`
        - Confidence: `{classification.confidence:.2f}`
        - Summary: {classification.summary or "No summary returned."}
        {primary_note}
        Reasons:
        {reasons}

        Suggested mock-scanner changes:
        {changes}

        Candidate files:
        {file_lines}

        This issue was filed automatically by the scheduled upstream watcher.
        """
    ).strip()


def create_issue(repo: str, base_sha: str, head_sha: str, files: list[ChangedFile], classification: Classification, primary: Classification | None) -> str:
    existing = issue_exists(repo, base_sha, head_sha)
    if existing:
        return existing
    title = f"Review upstream openvas-scanner changes {base_sha[:7]}..{head_sha[:7]}"
    labels = "upstream-openvas,compatibility"
    if classification.decision == "replicate":
        labels += ",needs-replication"
    else:
        labels += ",needs-human-review"
    body = issue_body(base_sha, head_sha, files, classification, primary)
    command = ["issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", labels]
    completed = gh(*command, check=False)
    if completed.returncode != 0 and "could not add label" in completed.stderr.lower():
        completed = gh("issue", "create", "--repo", repo, "--title", title, "--body", body)
    elif completed.returncode != 0:
        completed.check_returncode()
    return completed.stdout.strip()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-repo", default=DEFAULT_UPSTREAM_REPO)
    parser.add_argument("--upstream-dir", default=".upstream/openvas-scanner")
    parser.add_argument("--head-ref", default="main")
    parser.add_argument("--base-ref", default=os.environ.get("UPSTREAM_WATCH_BASE_REF", ""))
    parser.add_argument("--github-repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_GITHUB_REPO))
    parser.add_argument("--state-variable", default=DEFAULT_STATE_VARIABLE)
    parser.add_argument("--primary-model", default=os.environ.get("OLLAMA_PRIMARY_MODEL", DEFAULT_PRIMARY_MODEL))
    parser.add_argument("--escalation-model", default=os.environ.get("OLLAMA_ESCALATION_MODEL", DEFAULT_ESCALATION_MODEL))
    parser.add_argument("--confidence-threshold", type=float, default=float(os.environ.get("OLLAMA_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD)))
    parser.add_argument("--ollama-host", default="")
    parser.add_argument("--ollama-api-key", default="")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--max-patch-chars", type=int, default=60000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--update-state", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    upstream_dir = Path(args.upstream_dir)
    ensure_upstream_checkout(args.upstream_repo, upstream_dir, args.head_ref)
    head_sha = resolve_head(upstream_dir, args.head_ref)
    base_ref = args.base_ref or read_state(args.github_repo, args.state_variable)
    if not base_ref:
        print(f"No previous upstream state found. Current head is {head_sha}.")
        if args.update_state and not args.dry_run:
            write_state(args.github_repo, args.state_variable, head_sha)
            print(f"Initialized {args.state_variable}={head_sha}.")
        return 0
    base_sha = normalize_base(upstream_dir, base_ref, head_sha)
    if not base_sha:
        raise RuntimeError(f"Could not resolve base ref {base_ref!r}")
    if base_sha == head_sha:
        print(f"No new upstream commits since {base_sha}.")
        return 0

    all_files = changed_files(upstream_dir, base_sha, head_sha)
    candidate_files = prefilter(all_files)
    print(f"Upstream range {base_sha}..{head_sha}: {len(all_files)} changed files, {len(candidate_files)} candidates.")
    if not candidate_files:
        print("No relevant upstream files passed deterministic filtering.")
        if args.update_state and not args.dry_run:
            write_state(args.github_repo, args.state_variable, head_sha)
            print(f"Updated {args.state_variable}={head_sha}.")
        return 0

    stat = diff_stat(upstream_dir, base_sha, head_sha)
    patch = relevant_patch(upstream_dir, base_sha, head_sha, candidate_files, args.max_patch_chars)
    prompt = build_prompt(base_sha, head_sha, candidate_files, stat, patch)
    final, primary = classify(prompt, args)
    print(json.dumps({"decision": final.decision, "confidence": final.confidence, "model": final.model, "summary": final.summary}, indent=2))

    if final.decision in {"replicate", "needs-human-review"}:
        if args.dry_run:
            print("Dry run: would create issue.")
        else:
            issue_url = create_issue(args.github_repo, base_sha, head_sha, candidate_files, final, primary)
            print(f"Issue: {issue_url}")
    if args.update_state and not args.dry_run:
        write_state(args.github_repo, args.state_variable, head_sha)
        print(f"Updated {args.state_variable}={head_sha}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
