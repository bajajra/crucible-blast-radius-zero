"""The worker builder must return the image ID produced by this build."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-worker.sh"
IMAGE_ID = "sha256:" + "a" * 64


class BuildWorkerTests(unittest.TestCase):
    def run_builder(self, reported_id: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "docker"
            calls = root / "calls"
            fake.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
args = sys.argv[1:]
with Path(os.environ['FAKE_DOCKER_CALLS']).open('a') as stream:
    stream.write(' '.join(args) + '\\n')
if args[0] == 'build':
    Path(args[args.index('--iidfile') + 1]).write_text(os.environ['FAKE_IMAGE_ID'] + '\\n')
elif args[:2] == ['image', 'inspect']:
    if args[2] != os.environ['FAKE_IMAGE_ID']:
        raise SystemExit(1)
else:
    raise SystemExit(2)
""")
            fake.chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "FAKE_DOCKER_CALLS": str(calls), "FAKE_IMAGE_ID": reported_id}
            result = subprocess.run(["bash", str(SCRIPT)], text=True, capture_output=True, env=env)
            return result, calls.read_text().splitlines()

    def test_build_result_is_an_immutable_image_id(self):
        result, calls = self.run_builder(IMAGE_ID)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), IMAGE_ID)
        self.assertIn("--iidfile", calls[0])
        self.assertEqual(calls[1], "image inspect " + IMAGE_ID)

    def test_malformed_build_result_fails_closed(self):
        result, calls = self.run_builder("crucible-worker:latest")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
