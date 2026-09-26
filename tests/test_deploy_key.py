"""Only the inference credential may be transferred to the VM."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "install-inference-key.sh"


class InferenceTransferTests(unittest.TestCase):
    def test_filters_management_key_and_requires_private_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "local.env"
            source.write_text("VULTR_INFERENCE_API_KEY=INFERENCE_FAKE_KEY_123456789\n"
                              "VULTR_API_KEY=MANAGEMENT_FAKE_KEY_987654321\n")
            source.chmod(0o600)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text('#!/bin/sh\nfor arg do remote="$arg"; done\nsh -n -c "$remote" || exit 2\ncat > "$CAPTURE_FILE"\n')
            fake_ssh.chmod(0o755)
            capture = root / "received.env"
            environment = {**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                           "CAPTURE_FILE": str(capture)}
            command = [str(SCRIPT), "--target", "ubuntu@example.com", "--env-file", str(source), "--apply"]
            result = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            received = capture.read_text()
            self.assertIn("INFERENCE_FAKE_KEY_123456789", received)
            self.assertNotIn("MANAGEMENT_FAKE_KEY_987654321", received)
            source.chmod(0o644)
            capture.unlink()
            rejected = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(capture.exists())


if __name__ == "__main__":
    unittest.main()
