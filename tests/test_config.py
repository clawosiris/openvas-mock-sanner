import unittest

from openvas_mock_scanner.config import ConfigError, FailureAt, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = load_config({})
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.port, 8080)
        self.assertEqual(config.scenario, "success-basic")
        self.assertEqual(config.result_count, 12)
        self.assertEqual(config.host_count, 3)

    def test_valid_overrides(self):
        config = load_config(
            {
                "MOCK_HOST": "0.0.0.0",
                "MOCK_PORT": "9090",
                "MOCK_SCENARIO": "success-large-report",
                "MOCK_PAGE_SIZE": "25",
                "MOCK_FAILURE_AT": "results:2",
                "MOCK_CLOCK_START": "2026-02-03T04:05:06Z",
                "MOCK_LATENCY_MS": "10",
                "MOCK_RESULT_COUNT": "8",
                "MOCK_HOST_COUNT": "2",
                "MOCK_SEED": "demo",
                "MOCK_VT_METADATA_PATH": "/tmp/vt-metadata.json",
                "MOCK_TARGET_PROFILE": "/tmp/target-profile.json",
                "MOCK_FEED_STRICT": "true",
            }
        )
        self.assertEqual(config.port, 9090)
        self.assertEqual(config.failure_at, FailureAt("results", 2))
        self.assertEqual(config.result_count, 8)
        self.assertEqual(config.vt_metadata_path, "/tmp/vt-metadata.json")
        self.assertEqual(config.target_profile_path, "/tmp/target-profile.json")
        self.assertTrue(config.feed_strict)

    def test_openvasd_listening_alias(self):
        config = load_config({"LISTENING": "0.0.0.0:80"})
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 80)

        override = load_config({"LISTENING": "0.0.0.0:80", "MOCK_PORT": "8080"})
        self.assertEqual(override.port, 8080)

    def test_invalid_values_fail(self):
        cases = [
            {"MOCK_PORT": "0"},
            {"MOCK_PAGE_SIZE": "0"},
            {"MOCK_CLOCK_START": "not-a-date"},
            {"MOCK_LATENCY_MS": "-1"},
            {"MOCK_SCENARIO": "unknown"},
            {"MOCK_FAILURE_AT": "bogus"},
            {"LISTENING": "0.0.0.0"},
            {"MOCK_FEED_STRICT": "maybe"},
        ]
        for env in cases:
            with self.subTest(env=env):
                with self.assertRaises(ConfigError):
                    load_config(env)


if __name__ == "__main__":
    unittest.main()
