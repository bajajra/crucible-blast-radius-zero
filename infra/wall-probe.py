#!/usr/bin/env python3
"""Run inside a worker container to attest network and syscall behavior."""

import ctypes
import errno
import json
import platform
import socket
import ssl
import sys


def direct_egress_status() -> tuple[str, str | None]:
    """Report the socket outcome; the host must separately prove a DROP hit."""
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            return "LEAK", None
    except TimeoutError as exc:
        return "TIMEOUT", str(exc)
    except OSError as exc:
        return "TRANSPORT_ERROR", f"{type(exc).__name__}: {exc}"


def probe(host: str, ip: str, dns_name: str) -> dict:
    proof = {"hostname": socket.gethostname(), "uname": platform.uname()._asdict()}
    proof["direct_egress"], error = direct_egress_status()
    if error:
        proof["direct_egress_error"] = error

    try:
        with socket.create_connection((ip, 443), timeout=8) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as secured:
                proof["allowlisted_tls"] = secured.version()
    except OSError as exc:
        proof["allowlisted_tls"] = f"FAILED: {type(exc).__name__}: {exc}"

    try:
        socket.getaddrinfo(dns_name, 443)
        proof["external_dns"] = "LEAK"
    except socket.gaierror as exc:
        proof["external_dns"] = "UNRESOLVED"
        proof["external_dns_error"] = f"{type(exc).__name__}: {exc}"

    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME is otherwise unprivileged.
    code = ctypes.get_errno()
    proof["ptrace"] = "BLOCKED" if result == -1 and code == errno.EPERM else f"FAILED: result={result}, errno={code}"
    return proof


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: wall-probe.py <allowed_host> <pinned_ip> <unlisted_dns_name>")
    result = probe(*sys.argv[1:])
    print(json.dumps(result, sort_keys=True))
    if (result["direct_egress"] != "TIMEOUT" or
            not result["allowlisted_tls"].startswith("TLS") or
            result["external_dns"] != "UNRESOLVED" or
            result["ptrace"] != "BLOCKED"):
        raise SystemExit(1)
