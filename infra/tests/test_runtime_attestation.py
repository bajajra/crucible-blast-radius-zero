"""The optional runtime must not silently ignore the worker's seccomp JSON."""

import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "verify-runtime.py"
SPEC = importlib.util.spec_from_file_location("verify_runtime", SOURCE)
assert SPEC and SPEC.loader
verify_runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_runtime)


class RuntimeAttestationTests(unittest.TestCase):
    def test_accepts_only_the_explicit_oci_seccomp_netstack_systrap_runtime(self):
        entry = {
            "runsc-oci": {
                "path": "/usr/bin/runsc",
                "runtimeArgs": ["--oci-seccomp", "--network=sandbox", "--platform=systrap"],
                "status": {"features": "ignored by this check"},
            }
        }
        self.assertEqual(verify_runtime.validate_entry(entry), Path("/usr/bin/runsc"))

    def test_missing_seccomp_or_host_network_fails_closed(self):
        for args in (
            [],
            ["--network=sandbox", "--platform=systrap"],
            ["--oci-seccomp=false", "--network=sandbox", "--platform=systrap"],
            ["--oci-seccomp", "--network=host", "--platform=systrap"],
            ["--oci-seccomp", "--network=sandbox", "--platform=systrap", "--disable-seccomp"],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                verify_runtime.validate_entry({"runsc-oci": {"path": "/usr/bin/runsc", "runtimeArgs": args}})

    def test_unregistered_or_indirect_runtime_fails_closed(self):
        for runtimes in (
            {},
            {"runsc-oci": {"path": "runsc", "runtimeArgs": verify_runtime.RUNSC_ARGS}},
            {"runsc-oci": {"path": "/tmp/other-runtime", "runtimeArgs": verify_runtime.RUNSC_ARGS}},
            {"runsc-oci": {"path": "/usr/bin/runsc", "args": verify_runtime.RUNSC_ARGS}},
        ):
            with self.subTest(runtimes=runtimes), self.assertRaises(ValueError):
                verify_runtime.validate_entry(runtimes)


if __name__ == "__main__":
    unittest.main()
