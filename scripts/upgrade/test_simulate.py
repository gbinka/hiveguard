#!/usr/bin/env python3
import datetime as dt
import ipaddress
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import simulate


NOW = dt.datetime(2026, 10, 4, tzinfo=dt.timezone.utc)


def record(subject, expiry=None):
    return {"subject": subject, "expires_at": expiry, "reason": "test", "severity": 100}


def nft_document():
    items = [{"chain": {"family": "inet", "table": "hiveguard", "name": "input", "type": "filter",
                        "hook": "input", "prio": -10, "policy": "accept"}}]
    for name, version in simulate.SETS.items():
        items.append({"set": {"family": "inet", "table": "hiveguard", "name": name,
                              "type": f"ipv{version}_addr", "elem": []}})
        items.append({"rule": {"family": "inet", "table": "hiveguard", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip" if version == 4 else "ip6", "field": "saddr"}}, "right": "@" + name}},
            {"drop": None},
        ]}})
    return {"nftables": items}


class SimulatorTests(unittest.TestCase):
    def test_host_namespace_is_rejected_before_subprocesses(self):
        with patch("simulate.os.readlink", return_value="net:[123]"), patch("simulate.subprocess.Popen") as spawn:
            with self.assertRaisesRegex(simulate.CheckFailed, "host network namespace"):
                simulate.namespace_guard("net:[123]")
            spawn.assert_not_called()

    def test_nft_requires_one_drop_rule_for_each_managed_set(self):
        document = nft_document()
        self.assertEqual(simulate.nft_state(document), {4: [], 6: []})
        document["nftables"][-1] = document["nftables"][-3]
        with self.assertRaisesRegex(simulate.CheckFailed, "duplicated or missing"):
            simulate.nft_state(document)

    def test_ipv4_and_ipv6_prefix_range_and_wrapped_elements(self):
        self.assertEqual(simulate.element_interval({"prefix": {"addr": "192.0.2.0", "len": 24}}, 4),
                         (int(ipaddress.ip_address("192.0.2.0")), int(ipaddress.ip_address("192.0.2.255"))))
        self.assertEqual(simulate.element_interval({"elem": {"val": {"range": ["2001:db8::1", "2001:db8::9"]}}}, 6),
                         (int(ipaddress.ip_address("2001:db8::1")), int(ipaddress.ip_address("2001:db8::9"))))
        with self.assertRaises(simulate.CheckFailed):
            simulate.element_interval("192.0.2.1", 6)

    def test_union_covers_entire_cidr_not_just_first_address(self):
        bans = {"192.0.2.0/24": record("192.0.2.0/24"), "2001:db8::1/128": record("2001:db8::1/128")}
        halves = [simulate.element_interval(value, 4) for value in ["192.0.2.0/25", "192.0.2.128/25"]]
        coverage = {4: simulate.merge_intervals(halves), 6: [simulate.element_interval("2001:db8::/64", 6)]}
        self.assertEqual(simulate.missing_coverage(bans, coverage, NOW), 0)
        coverage[4] = halves[:1]
        self.assertEqual(simulate.missing_coverage(bans, coverage, NOW), 1)
        coverage[6] = []
        self.assertEqual(simulate.missing_coverage(bans, coverage, NOW), 2)

    def test_roundtrip_allows_natural_expiry_but_rejects_changed_active_record(self):
        expired = record("192.0.2.1/32", "2026-10-03T00:00:00Z")
        permanent = record("192.0.2.2/32")
        expected = {expired["subject"]: expired, permanent["subject"]: permanent}
        actual = {permanent["subject"]: permanent}
        simulate.compare_roundtrip(expected, actual, NOW)
        actual = {permanent["subject"]: {**permanent, "reason": "changed"}}
        with self.assertRaisesRegex(simulate.CheckFailed, "changed_active=1"):
            simulate.compare_roundtrip(expected, actual, NOW)
        with self.assertRaisesRegex(simulate.CheckFailed, "missing_active=1"):
            simulate.compare_roundtrip(expected, {}, NOW)

    def test_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wal.bin").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(simulate.CheckFailed, "symlink"):
                simulate.tree_hashes(root)


if __name__ == "__main__":
    unittest.main()
