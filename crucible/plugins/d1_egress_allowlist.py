"""D1 exact-host network policy for brokered actions."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from crucible.network_policy import SAFE_FETCH_URLS
from crucible.plugins_api import Action, Verdict


class EgressAllowlistPlugin:
    id = "d1_egress_allowlist_v1"
    dimension = "D1"
    triggers = ("egress", "exfil", "dependency_fetch", "lookalike")

    def __init__(self, allowed_hosts: set[str] | frozenset[str]) -> None:
        self.allowed_hosts = frozenset(host.rstrip(".").lower() for host in allowed_hosts)
        if not self.allowed_hosts:
            raise ValueError("network allowlist cannot be empty")

    def pre_exec(self, action: Action) -> Verdict:
        if action.kind not in {"http_get", "net_connect"}:
            return Verdict("allow", "not a brokered network action", self.dimension, plugin_id=self.id)
        raw = str(action.payload.get("url") or action.payload.get("host") or "")
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host:
            return Verdict("deny", "missing destination host", self.dimension, plugin_id=self.id)
        if parsed.username is not None or parsed.password is not None:
            return Verdict("deny", "credentials in destination URL are forbidden", self.dimension, plugin_id=self.id)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return Verdict("deny", "IP literal destination requires an explicit host policy", self.dimension, plugin_id=self.id)
        if parsed.scheme not in {"https", ""} or parsed.port not in {None, 443}:
            return Verdict("deny", "only HTTPS on port 443 is permitted", self.dimension, plugin_id=self.id)
        if host not in self.allowed_hosts:
            return Verdict("deny", f"destination {host} is not allowlisted", self.dimension, plugin_id=self.id)
        if raw not in SAFE_FETCH_URLS:
            return Verdict("deny", "network URL is not approved", self.dimension, plugin_id=self.id)
        return Verdict("allow", f"exact allowlist match: {host}", self.dimension, plugin_id=self.id)
