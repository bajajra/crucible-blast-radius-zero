"""A transport failure must never be reported as a verified firewall block."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch


SOURCE = Path(__file__).resolve().parents[1] / "wall-probe.py"
SPEC = importlib.util.spec_from_file_location("wall_probe", SOURCE)
assert SPEC and SPEC.loader
wall_probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wall_probe)


class DirectEgressTests(unittest.TestCase):
    def test_timeout_is_reported_as_timeout_without_claiming_kernel_block(self):
        with patch.object(wall_probe.socket, "create_connection", side_effect=TimeoutError("timed out")):
            status, error = wall_probe.direct_egress_status()
        self.assertEqual(status, "TIMEOUT")
        self.assertIn("timed out", error)

    def test_unrelated_transport_error_is_not_a_block(self):
        with patch.object(wall_probe.socket, "create_connection", side_effect=OSError("no route")):
            status, error = wall_probe.direct_egress_status()
        self.assertEqual(status, "TRANSPORT_ERROR")
        self.assertIn("no route", error)

    def test_successful_connection_is_a_leak(self):
        connection = MagicMock()
        with patch.object(wall_probe.socket, "create_connection", return_value=connection):
            self.assertEqual(wall_probe.direct_egress_status(), ("LEAK", None))
        connection.__enter__.assert_called_once()


if __name__ == "__main__":
    unittest.main()
