"""The public export must never copy private episode text into Pages."""

import json
from pathlib import Path
import tempfile
import unittest

from crucible.experience import ExperienceBank
from crucible.public_demo import APPROVED_REPORTS, export, public_snapshot


class PublicDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "bank.sqlite"
        self.site = self.root / "site"

    def tearDown(self):
        self.temp.cleanup()

    def test_closed_schema_drops_all_free_form_text(self):
        secret = "UNKNOWN_SECRET_8ef145e51"
        source = {
            "summary": {"total": 1, "docker": 1, "simulated": 0,
                        "unverified_docker": 0, "attack_rate": 0,
                        "safe_rate": 1, "fixture_rate": 0,
                        "extra": secret},
            "curves": [{"episode": 1, "round": 1, "attack_rate": 0,
                        "safe_rate": 1, "host_ip": secret}],
            "events": [{"round": 1, "action": "http_get", "detail": secret,
                        "decision": "deny", "dimension": "d6_output_filter_v1",
                        "reason": secret, "mode": "docker", "exit_code": None,
                        "url": "https://example.com/?key=" + secret}],
            "patterns": [{"pattern_id": secret, "attack_shape": "secret_exfil",
                          "dimension": "D6", "recommended_defense": secret,
                          "supporting_count": 1}],
            "latest_report": {"text": secret, "episode_id": secret,
                              "mode": "docker"},
            "extra": secret,
        }
        result = public_snapshot(source)
        body = json.dumps(result)
        self.assertNotIn(secret, body)
        self.assertEqual(result["events"][0]["dimension"], "D6 output filter")
        self.assertEqual(result["events"][0]["detail"], "")
        self.assertEqual(result["patterns"][0]["recommended_defense"], "Outbound secret scan")
        self.assertIsNone(result["latest_report"])

    def test_export_has_no_unknown_secret_even_when_bank_contains_it(self):
        secret = "UNKNOWN_SECRET_5d9ec45a"
        bank = ExperienceBank(self.db)
        bank.add_episode({
            "episode_id": "episode_" + secret, "round": 1,
            "attack_shape": "secret_exfil", "flag_captured": False,
            "flag_verifiable": True, "safe_action_executed": True,
            "task_completed": True, "containment_held": True,
            "execution_mode": "docker", "final_report": secret,
            "worker_trajectory": [{"action": {"kind": "http_get",
                                               "payload": {"url": "https://example.com/" + secret}},
                                   "decision": "deny", "by": secret,
                                   "reason": secret, "result": {"exit_code": None}}],
            "boundary_verdicts": [],
            "blue_action": {"plugin_id": secret},
        })
        summary = export(self.db, self.site, require_docker=True)
        self.assertEqual(summary["docker"], 1)
        html = (self.site / "index.html").read_text()
        body = (self.site / "snapshot.json").read_text()
        self.assertNotIn(secret, html + body)
        self.assertNotIn("/api/snapshot", html)
        self.assertIn("./snapshot.json", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertEqual(json.loads(body)["patterns"][0]["attack_shape"],
                         "Secret in outbound request")

    def test_only_exact_approved_report_is_public(self):
        report = sorted(APPROVED_REPORTS)[0]
        result = public_snapshot({"latest_report": {"text": report,
                                                    "mode": "docker",
                                                    "episode_id": "private-id"}})
        self.assertEqual(result["latest_report"]["text"], report)
        self.assertNotIn("private-id", json.dumps(result))

    def test_pages_gate_rejects_simulation_only(self):
        bank = ExperienceBank(self.db)
        bank.add_episode({"episode_id": "sim", "round": 1,
                          "attack_shape": "egress", "flag_captured": False,
                          "safe_action_executed": True, "execution_mode": "simulate"})
        with self.assertRaisesRegex(ValueError, "requires at least one Docker"):
            export(self.db, self.site, require_docker=True)
        self.assertFalse(self.site.exists())

    def test_output_symlinks_are_rejected(self):
        ExperienceBank(self.db)
        self.site.mkdir()
        (self.site / "index.html").symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "cannot be a symlink"):
            export(self.db, self.site)


if __name__ == "__main__":
    unittest.main()
