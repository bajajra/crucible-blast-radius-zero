"""Guard against weakening the worker syscall boundary during profile edits."""

import json
from pathlib import Path
import unittest


class SeccompProfileTests(unittest.TestCase):
    def test_default_deny_and_sensitive_syscalls(self):
        profile = json.loads((Path(__file__).resolve().parents[1] / "crucible-seccomp.json").read_text())
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        direct_allow = {
            name
            for rule in profile["syscalls"]
            if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("includes")
            for name in rule["names"]
        }
        self.assertTrue({"read", "write", "execve"}.issubset(direct_allow))
        self.assertFalse({"ptrace", "process_vm_readv", "process_vm_writev", "socketcall",
                          "unshare", "setns", "mount", "bpf"} & direct_allow)


if __name__ == "__main__":
    unittest.main()
