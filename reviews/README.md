# Reviewer Findings

Optional reviewer findings live here, one file per implementation.

Suggested workflow:

1. Run GitHub Copilot code review, or another reviewer model, on one implementation at a time.
2. Normalize the findings into JSON.
3. Save them as `reviews/<implementation>.json`.
4. Run `python3 harness/quality_score.py --reviews-root reviews`.

The quality scorer only counts findings that are confirmed or reproducible.

## File format

Use a JSON object with a `findings` array.

Example:

```json
{
  "reviewer": "github-copilot",
  "reviewed_at": "2026-05-17T15:00:00Z",
  "findings": [
    {
      "title": "Result delay is ignored",
      "severity": "high",
      "category": "correctness",
      "status": "confirmed",
      "confirmed": true,
      "reproducible": true,
      "notes": "Server returns findings on first poll despite MOCK_FINDINGS_DELAY_POLLS=2"
    }
  ]
}
```

Accepted severities:

- `critical`
- `high`
- `medium`
- `low`
- `nit`
