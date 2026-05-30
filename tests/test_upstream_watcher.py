import json
import unittest

from tools import upstream_openvas_watcher as watcher


class UpstreamWatcherTests(unittest.TestCase):
    def test_prefilter_keeps_openvasd_api_changes(self):
        files = [
            watcher.ChangedFile("M", "rust/src/openvasd/response.rs"),
            watcher.ChangedFile("M", "docs/changelog.md"),
            watcher.ChangedFile("M", "misc/scanner_status.c"),
        ]

        self.assertEqual(
            [item.path for item in watcher.prefilter(files)],
            ["rust/src/openvasd/response.rs", "misc/scanner_status.c"],
        )

    def test_prefilter_ignores_unrelated_docs(self):
        files = [
            watcher.ChangedFile("M", "README.md"),
            watcher.ChangedFile("M", "docs/development-notes.md"),
        ]

        self.assertEqual(watcher.prefilter(files), [])

    def test_parse_classification_accepts_json_wrapped_in_text(self):
        raw = "```json\n" + json.dumps(
            {
                "decision": "replicate",
                "confidence": 0.91,
                "summary": "Status payload changed.",
                "reasons": ["status JSON shape changed"],
                "suggested_changes": ["Update status fixture."],
            }
        ) + "\n```"

        classification = watcher.parse_classification(raw, "qwen2.5-coder:7b")

        self.assertEqual(classification.decision, "replicate")
        self.assertEqual(classification.confidence, 0.91)
        self.assertEqual(classification.reasons, ("status JSON shape changed",))
        self.assertEqual(classification.suggested_changes, ("Update status fixture.",))

    def test_build_prompt_names_scope_and_range(self):
        prompt = watcher.build_prompt(
            "base",
            "head",
            [watcher.ChangedFile("M", "rust/src/openvasd/result.rs")],
            " result.rs | 2 +-",
            "diff --git a/rust/src/openvasd/result.rs b/rust/src/openvasd/result.rs",
        )

        self.assertIn("openvasd HTTP routes", prompt)
        self.assertIn("base..head", prompt)
        self.assertIn("rust/src/openvasd/result.rs", prompt)

    def test_issue_state_body_contains_parseable_commit(self):
        sha = "f039649b0191d12f859128724da0d03dfe73e87a"
        body = watcher.state_issue_body(sha)

        self.assertIn(watcher.STATE_ISSUE_MARKER, body)
        self.assertIn(f"```text\n{sha}\n```", body)


if __name__ == "__main__":
    unittest.main()
