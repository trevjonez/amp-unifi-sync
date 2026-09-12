#!/usr/bin/env python3
"""Unit tests for sync.py — stdlib unittest, no dependencies.

    python3 -m unittest -v          (or)   python3 test_sync.py

The kvp fixtures below are trimmed from real AMP instance files, so the parser
is tested against the shapes AMP actually writes rather than invented ones.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import sync


# --- fixtures ---------------------------------------------------------------

FACTORIO_PORTS = json.dumps([
    {"Protocol": 1, "Port": 34197, "Range": 1, "Ref": "ServerPort", "Name": "Server Port"},
    {"Protocol": 0, "Port": 7777, "Range": 1, "Ref": "RCONPort", "Name": "RCON Port"},
])
VALHEIM_PORTS = json.dumps([
    {"Protocol": 1, "Port": 2456, "Range": 1, "Ref": "ApplicationPort1", "Name": "Game Port"},
    {"Protocol": 1, "Port": 2457, "Range": 1, "Ref": "ApplicationPort2", "Name": "Steam Query"},
])
ZOMBOID_PORTS = json.dumps([
    {"Protocol": 1, "Port": 16261, "Range": 1, "Ref": "ApplicationPort1", "Name": "Steam"},
    {"Protocol": 1, "Port": 16262, "Range": 1, "Ref": "ApplicationPort2", "Name": "Direct"},
    {"Protocol": 0, "Port": 27015, "Range": 1, "Ref": "RemoteAdminPort", "Name": "RCON"},
])
BANNERLORD_PORTS = json.dumps([
    {"Protocol": 2, "Port": 7210, "Range": 1, "Ref": "ServerPort", "Name": "Game and Web Admin"},
])
# Mixed protocols on one instance — exercises the game-<proto> suffix path.
MIXED_PORTS = json.dumps([
    {"Protocol": 1, "Port": 5000, "Range": 1, "Ref": "ApplicationPort1", "Name": "udp"},
    {"Protocol": 0, "Port": 6000, "Range": 1, "Ref": "ApplicationPort2", "Name": "tcp"},
])
# Range > 1 must expand and merge into a contiguous span.
SPAN_PORTS = json.dumps([
    {"Protocol": 1, "Port": 9000, "Range": 3, "Ref": "ServerPort", "Name": "span"},
])


def write_instance(root: str, name: str, *, generic: str | None = None,
                   mc_port: str | None = None, sftp: tuple[str, str] | None = None) -> None:
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    if generic is not None:
        with open(os.path.join(d, "GenericModule.kvp"), "w") as fh:
            fh.write("# a comment line\n")
            fh.write("Meta.DisplayName=Test Game\n")
            fh.write(f"App.Ports={generic}\n")
    if mc_port is not None:
        with open(os.path.join(d, "MinecraftModule.kvp"), "w") as fh:
            fh.write(f"Minecraft.PortNumber={mc_port}\n")
    if sftp is not None:
        enabled, port = sftp
        with open(os.path.join(d, "FileManagerPlugin.kvp"), "w") as fh:
            fh.write(f"SFTP.SFTPEnabled={enabled}\nSFTP.SFTPPortNumber={port}\n")


def inst(name: str, state: int, *, module: str = "GenericModule",
         running: bool = True, suspended: bool = False) -> dict:
    return {"InstanceName": name, "Module": module, "AppState": state,
            "Running": running, "Suspended": suspended}


class PortSpecTests(unittest.TestCase):
    def test_expand_single_range_and_list(self):
        self.assertEqual(sync.expand_ports("25565"), {25565})
        self.assertEqual(sync.expand_ports("2456-2457"), {2456, 2457})
        self.assertEqual(sync.expand_ports("2226,2230"), {2226, 2230})
        self.assertEqual(sync.expand_ports("16261-16262,27015"), {16261, 16262, 27015})

    def test_expand_tolerates_junk(self):
        self.assertEqual(sync.expand_ports(""), set())
        self.assertEqual(sync.expand_ports(None), set())
        self.assertEqual(sync.expand_ports("abc"), set())
        self.assertEqual(sync.expand_ports("80,,443"), {80, 443})

    def test_protos_overlap(self):
        self.assertTrue(sync.protos_overlap("tcp", "tcp"))
        self.assertTrue(sync.protos_overlap("tcp", "tcp_udp"))
        self.assertTrue(sync.protos_overlap("tcp_udp", "udp"))
        self.assertFalse(sync.protos_overlap("tcp", "udp"))

    def test_merge_ranges(self):
        self.assertEqual(sync.merge_ranges([2456, 2457]), ["2456-2457"])
        self.assertEqual(sync.merge_ranges([25565]), ["25565"])
        self.assertEqual(sync.merge_ranges([80, 443]), ["80", "443"])
        self.assertEqual(sync.merge_ranges([3, 1, 2]), ["1-3"])


class CollisionTests(unittest.TestCase):
    """The anti-clobber guard. A regression here means duplicate or conflicting
    forwards on top of hand-managed rules."""

    def test_combined_foreign_rule_reserves_each_port(self):
        # Regression: 'AMP - SFTP' covers "2226,2230". A string comparison missed
        # it and would have created duplicate forwards on both ports.
        reserved = sync.build_reservations(
            [{"name": "AMP - SFTP", "dst_port": "2226,2230", "proto": "tcp_udp"}])
        self.assertEqual(sync.find_collision(reserved, "2226", "tcp"), "AMP - SFTP")
        self.assertEqual(sync.find_collision(reserved, "2230", "tcp"), "AMP - SFTP")
        self.assertIsNone(sync.find_collision(reserved, "2227", "tcp"))

    def test_range_foreign_rule_reserves_interior_ports(self):
        reserved = sync.build_reservations(
            [{"name": "Zomboid", "dst_port": "16261-16262", "proto": "udp"}])
        self.assertEqual(sync.find_collision(reserved, "16262", "udp"), "Zomboid")
        self.assertEqual(sync.find_collision(reserved, "16261-16262", "udp"), "Zomboid")
        self.assertIsNone(sync.find_collision(reserved, "16263", "udp"))

    def test_partial_overlap_still_collides(self):
        reserved = sync.build_reservations(
            [{"name": "X", "dst_port": "2456-2457", "proto": "udp"}])
        self.assertEqual(sync.find_collision(reserved, "2457-2458", "udp"), "X")

    def test_different_protocol_does_not_collide(self):
        reserved = sync.build_reservations(
            [{"name": "X", "dst_port": "25565", "proto": "tcp"}])
        self.assertIsNone(sync.find_collision(reserved, "25565", "udp"))

    def test_tcp_udp_collides_with_either(self):
        reserved = sync.build_reservations(
            [{"name": "X", "dst_port": "7210", "proto": "udp"}])
        self.assertEqual(sync.find_collision(reserved, "7210", "tcp_udp"), "X")

    def test_no_foreign_rules_means_no_collision(self):
        self.assertIsNone(sync.find_collision(sync.build_reservations([]), "1234", "tcp"))


class InstancePortTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = sync.AMP_INSTANCES_DIR
        sync.AMP_INSTANCES_DIR = self.tmp.name
        self.addCleanup(lambda: setattr(sync, "AMP_INSTANCES_DIR", self._orig))

    def test_rcon_is_never_forwarded(self):
        write_instance(self.tmp.name, "Fac", generic=FACTORIO_PORTS, sftp=("True", "2227"))
        specs = sync.instance_ports("Fac", "GenericModule")
        self.assertIn(("game", "34197", "udp"), specs)
        self.assertIn(("sftp", "2227", "tcp"), specs)
        self.assertNotIn(7777, [int(p) for _, p, _ in specs])

    def test_zomboid_rcon_excluded_and_ports_merged(self):
        write_instance(self.tmp.name, "PZ", generic=ZOMBOID_PORTS)
        specs = sync.instance_ports("PZ", "GenericModule")
        self.assertEqual(specs, [("game", "16261-16262", "udp")])

    def test_valheim_secondary_port_is_included(self):
        # ApplicationEndpoints omits 2457; the kvp parser must not.
        write_instance(self.tmp.name, "Val", generic=VALHEIM_PORTS)
        self.assertEqual(sync.instance_ports("Val", "GenericModule"),
                         [("game", "2456-2457", "udp")])

    def test_protocol_two_means_both(self):
        write_instance(self.tmp.name, "BL", generic=BANNERLORD_PORTS)
        self.assertEqual(sync.instance_ports("BL", "GenericModule"),
                         [("game", "7210", "tcp_udp")])

    def test_minecraft_uses_scalar_port_and_is_tcp(self):
        write_instance(self.tmp.name, "MC", mc_port="25568", sftp=("True", "2226"))
        specs = sync.instance_ports("MC", "MinecraftModule")
        self.assertIn(("game", "25568", "tcp"), specs)
        self.assertIn(("sftp", "2226", "tcp"), specs)

    def test_sftp_disabled_is_omitted(self):
        write_instance(self.tmp.name, "Off", generic=FACTORIO_PORTS, sftp=("False", "2299"))
        self.assertNotIn("sftp", [k for k, _, _ in sync.instance_ports("Off", "GenericModule")])

    def test_mixed_protocols_get_distinct_names(self):
        write_instance(self.tmp.name, "Mix", generic=MIXED_PORTS)
        kinds = sorted(k for k, _, _ in sync.instance_ports("Mix", "GenericModule"))
        self.assertEqual(kinds, ["game-tcp", "game-udp"])

    def test_range_field_expands(self):
        write_instance(self.tmp.name, "Span", generic=SPAN_PORTS)
        self.assertEqual(sync.instance_ports("Span", "GenericModule"),
                         [("game", "9000-9002", "udp")])

    def test_missing_files_yield_nothing(self):
        os.makedirs(os.path.join(self.tmp.name, "Empty"))
        self.assertEqual(sync.instance_ports("Empty", "GenericModule"), [])

    def test_malformed_app_ports_does_not_raise(self):
        d = os.path.join(self.tmp.name, "Bad")
        os.makedirs(d)
        with open(os.path.join(d, "GenericModule.kvp"), "w") as fh:
            fh.write("App.Ports=not json at all\n")
        self.assertEqual(sync.instance_ports("Bad", "GenericModule"), [])


class DesiredStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = sync.AMP_INSTANCES_DIR
        sync.AMP_INSTANCES_DIR = self.tmp.name
        self.addCleanup(lambda: setattr(sync, "AMP_INSTANCES_DIR", self._orig))
        write_instance(self.tmp.name, "Fac", generic=FACTORIO_PORTS, sftp=("True", "2227"))

    def game(self, want):
        return want["[amp-sync] Fac game"]["enabled"]

    def sftp(self, want):
        return want["[amp-sync] Fac sftp"]["enabled"]

    def test_running_is_enabled(self):
        want = sync.desired_state([inst("Fac", 20)], {})
        self.assertTrue(self.game(want))

    def test_settled_stop_closes_only_after_debounce(self):
        streak: dict[str, int] = {}
        seen = [self.game(sync.desired_state([inst("Fac", 0)], streak)) for _ in range(4)]
        self.assertEqual(seen, [True, True, False, False],
                         "a stop must persist DEBOUNCE_POLLS polls before closing")

    def test_crash_loop_never_closes(self):
        # The specific regression the debounce exists to prevent.
        streak: dict[str, int] = {}
        for state in [20, 40, 10, 20, 40, 10, 20, 40, 10]:
            self.assertTrue(self.game(sync.desired_state([inst("Fac", state)], streak)),
                            f"crash-loop state {state} must not close the port")
        self.assertEqual(streak["Fac"], 0)

    def test_sleeping_stays_open(self):
        # Wake-on-connect: closing the port would strand the server.
        streak: dict[str, int] = {}
        for _ in range(5):
            self.assertTrue(self.game(sync.desired_state([inst("Fac", 50)], streak)))

    def test_failed_and_suspended_count_as_stopped(self):
        for state in (100, 200):
            streak: dict[str, int] = {}
            seen = [self.game(sync.desired_state([inst("Fac", state)], streak))
                    for _ in range(sync.DEBOUNCE_POLLS)]
            self.assertFalse(seen[-1], f"state {state} should settle closed")

    def test_recovery_resets_the_streak(self):
        streak: dict[str, int] = {}
        sync.desired_state([inst("Fac", 0)], streak)
        sync.desired_state([inst("Fac", 0)], streak)
        sync.desired_state([inst("Fac", 20)], streak)
        self.assertEqual(streak["Fac"], 0)
        self.assertTrue(self.game(sync.desired_state([inst("Fac", 0)], streak)))

    def test_sftp_follows_instance_not_application(self):
        # Stopped game, instance up: SFTP must stay open (that is when you want it).
        streak: dict[str, int] = {}
        for _ in range(sync.DEBOUNCE_POLLS + 1):
            want = sync.desired_state([inst("Fac", 0)], streak)
        self.assertFalse(self.game(want))
        self.assertTrue(self.sftp(want))

    def test_sftp_closes_when_instance_down(self):
        want = sync.desired_state([inst("Fac", 0, running=False)], {})
        self.assertFalse(self.sftp(want))

    def test_sftp_closes_when_instance_suspended(self):
        want = sync.desired_state([inst("Fac", 20, suspended=True)], {})
        self.assertFalse(self.sftp(want))

    def test_excluded_instances_produce_nothing(self):
        write_instance(self.tmp.name, "Main", sftp=("True", "2223"))
        want = sync.desired_state([inst("Main", -1, module="ADSModule")], {})
        self.assertEqual(want, {}, "ADS controller must never be forwarded")

    def test_rule_names_carry_the_marker(self):
        want = sync.desired_state([inst("Fac", 20)], {})
        for name in want:
            self.assertTrue(name.startswith(sync.MARKER))


class BuildDocTests(unittest.TestCase):
    def test_doc_matches_current_udm_schema(self):
        doc = sync.build_doc("[amp-sync] Fac game",
                             {"port": "34197", "proto": "udp", "enabled": True}, "site123")
        self.assertEqual(doc["dst_port"], "34197")
        self.assertEqual(doc["fwd_port"], "34197")
        self.assertEqual(doc["site_id"], "site123")
        self.assertEqual(doc["destination_ip"], "any")
        self.assertEqual(doc["destination_ips"], [])
        self.assertFalse(doc["src_limiting_enabled"])
        # The legacy 'src' field belongs only to pre-refactor documents; mixing it
        # with src_limiting_enabled produces a malformed rule.
        self.assertNotIn("src", doc)
        self.assertNotIn("_id", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
