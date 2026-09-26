"""Pure secret scanner shared by the host policy and disposable worker.

The worker image includes this module so result text is redacted before its
JSON record crosses the container boundary. The host scans that record again.
"""

from __future__ import annotations

import re
from base64 import b64encode, urlsafe_b64encode


# The deliberately fake scenario marker is included in the worker image so
# its encoded forms can be recognized without sending any host credential in.
DEMO_CANARY = "CRUCIBLE_CANARY_FAKE_KEY_7e19c2c0d1"

_PATTERNS = (
    re.compile(r"(?i)\b(?:VULTR[_-]?(?:INFERENCE[_-]?)?API[_-]?KEY|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bCRUCIBLE_CANARY_FAKE_KEY_[A-Za-z0-9]+\b"),
    re.compile(r"(?i)(?:[?&](?:api_?key|token|secret|license_?key)=)[^&#\s]{8,}"),
)


class SecretScanner:
    def __init__(self, canaries: tuple[str, ...] = ()) -> None:
        self.canaries = tuple(value for value in canaries if value)
        self.encoded_canaries = tuple(sorted({variant for canary in self.canaries
            for variant in (
                b64encode(canary.encode()).decode(),
                b64encode(canary.encode()).decode().rstrip("="),
                urlsafe_b64encode(canary.encode()).decode(),
                urlsafe_b64encode(canary.encode()).decode().rstrip("="),
                canary.encode().hex(), canary.encode().hex().upper(),
                "".join(f"%{byte:02X}" for byte in canary.encode()),
                "".join(f"%{byte:02x}" for byte in canary.encode()),
            ) if variant != canary and len(variant) >= 8}, key=len, reverse=True))

    def redact(self, value: str) -> tuple[str, int]:
        count = 0
        clean = value
        for canary in (*self.encoded_canaries, *self.canaries):
            matches = clean.count(canary)
            if matches:
                clean = clean.replace(canary, "[REDACTED-CANARY]")
                count += matches
        for pattern in _PATTERNS:
            clean, matches = pattern.subn("[REDACTED-SECRET]", clean)
            count += matches
        return clean, count
