#!/usr/bin/env python3
"""
Reconcile UniFi (UDM) port forwards against CubeCoders AMP instance state.

AMP is the source of truth. Each instance's declared game ports (and its SFTP
port) become a WAN port forward, enabled while that instance's application is
intended to be running and disabled when it is not.

OWNERSHIP -- the safety property this tool is built around:

  owned    forwards whose name starts with MARKER (default "[amp-sync]").
           The ONLY documents this tool will ever POST / PUT / DELETE.
  foreign  every other forward (Reverse Proxy, Tesla, TeamSpeak, anything you
           add by hand). Read, never written. Their (port, proto) pairs are
           treated as RESERVED: a desired rule that would collide is skipped
           with a warning rather than duplicating or overwriting.

The delete path filters on MARKER before diffing, so a bug in desired-state
computation can at worst remove rules this tool created. It is structurally
incapable of touching a hand-managed forward.

WHERE THE DATA COMES FROM

  state  AMP API, ADSModule/GetInstances -> AppState (per-instance app state).
         The AMP CLI only reports whether the instance daemon is up, never the
         application, so the API is the only usable source.
  ports  the instance kvp files on disk (read-only bind mount). The API's
         ApplicationEndpoints field is protocol-blind and lists only the
         primary port -- it omits e.g. Valheim's Steam query port 2457 -- so it
         cannot be used to derive forwards.

Usage:
  ./sync.py --dry-run      # print the diff, change nothing
  ./sync.py --once         # one reconcile pass, then exit
  ./sync.py                # loop forever at --interval
  ./sync.py --adopt        # one-time: rename pre-existing rules into ownership
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

MARKER = os.environ.get("MARKER", "[amp-sync]")

# No site-specific defaults: every address is supplied by the environment, so
# nothing about a particular network is baked into the image.
AMP_URL = os.environ.get("AMP_URL", "")
AMP_USER = os.environ.get("AMP_USER", "")
AMP_PASS = os.environ.get("AMP_PASS", "")
AMP_INSTANCES_DIR = os.environ.get("AMP_INSTANCES_DIR", "/amp")

UNIFI_HOST = os.environ.get("UNIFI_HOST", "")
UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")

# Forward destination: the address AMP's game servers listen on.
FWD_TARGET = os.environ.get("AMP_TARGET_IP", "")
# "wan" = primary WAN only; "both"/"all" = every WAN.
PFWD_INTERFACE = os.environ.get("PFWD_INTERFACE", "wan")

# Consecutive settled-stopped polls required before a forward is disabled.
# Guards against restart loops: a crash-looping server cycles Ready->Stopping->
# Starting every couple of minutes, and without this the UDM config would be
# rewritten continuously.
DEBOUNCE_POLLS = int(os.environ.get("DEBOUNCE_POLLS", "3"))

# The stopped-streak has to outlive the process, or --once could never reach the
# debounce threshold and would leave stopped servers forwarded forever.
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/amp-unifi-sync/state.json")

# ADS is the control panel, not a game server. Excluded so its SFTP port (2223)
# is never WAN-exposed. Comma-separated to override.
EXCLUDE_INSTANCES = {
    s.strip() for s in os.environ.get("EXCLUDE_INSTANCES", "Main").split(",") if s.strip()
}

# Administrative ports. Never WAN-forwarded, regardless of instance state.
EXCLUDED_PORT_REFS = {"RCONPort", "RemoteAdminPort"}

# AMP ApplicationState. A stopped application is only 0/100/200; every other
# value means AMP is actively doing something and the port should stay open.
# 50 (Sleeping) is load-bearing: Minecraft idle-sleep wakes on an inbound
# connection, so closing its forward would make it unable to ever wake.
STATE_NAMES = {
    -1: "Undefined", 0: "Stopped", 5: "PreStart", 7: "Configuring", 10: "Starting",
    20: "Ready", 30: "Restarting", 40: "Stopping", 45: "PreparingForSleep",
    50: "Sleeping", 60: "Waiting", 70: "Installing", 75: "Updating",
    80: "AwaitingUserInput", 100: "Failed", 200: "Suspended", 250: "Maintenance",
    999: "Indeterminate",
}
STOPPED_STATES = {0, 100, 200}

PROTO = {0: "tcp", 1: "udp", 2: "tcp_udp"}


# ---------------------------------------------------------------- http helpers

def _request(url: str, method: str, headers: dict, body: dict | None, insecure: bool):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    # The UDM serves a self-signed cert; this is the curl -k equivalent.
    ctx = ssl._create_unverified_context() if insecure else None
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip() else None


# ------------------------------------------------------------------ AMP client

def amp_login() -> str:
    res = _request(
        f"{AMP_URL}/API/Core/Login", "POST",
        {"Content-Type": "application/json", "Accept": "application/json"},
        {"username": AMP_USER, "password": AMP_PASS, "token": "", "rememberMe": False},
        insecure=False,
    )
    sess = (res or {}).get("sessionID")
    if not sess:
        raise RuntimeError("AMP login failed (check AMP_USER / AMP_PASS)")
    return sess


def amp_instances(session: str) -> list[dict]:
    res = _request(
        f"{AMP_URL}/API/ADSModule/GetInstances", "POST",
        {"Content-Type": "application/json", "Accept": "application/json"},
        {"SESSIONID": session}, insecure=False,
    )
    # Shape has varied across AMP versions: either a flat list of instances or a
    # list of targets each holding AvailableInstances. Walk for the leaf dicts.
    out: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if "InstanceName" in node and "AppState" in node:
                out.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(res)
    return out


# ------------------------------------------------------------- kvp port source

def read_kvp(path: str) -> dict[str, str]:
    vals: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                vals[k.strip()] = v
    except FileNotFoundError:
        pass
    return vals


def merge_ranges(ports: list[int]) -> list[str]:
    """[2456,2457] -> ['2456-2457'];  [25565] -> ['25565']"""
    out: list[str] = []
    for p in sorted(set(ports)):
        if out:
            lo, _, hi = out[-1].partition("-")
            end = int(hi or lo)
            if p == end + 1:
                out[-1] = f"{lo}-{p}"
                continue
        out.append(str(p))
    return out


def instance_ports(name: str, module: str) -> list[tuple[str, str, str]]:
    """Return [(kind, port_or_range, proto)] for one instance, from its kvp files."""
    base = os.path.join(AMP_INSTANCES_DIR, name)
    specs: list[tuple[str, str, str]] = []

    if "Minecraft" in module:
        mc = read_kvp(os.path.join(base, "MinecraftModule.kvp"))
        port = mc.get("Minecraft.PortNumber", "").strip()
        if port.isdigit():
            specs.append(("game", port, "tcp"))
    else:
        gen = read_kvp(os.path.join(base, "GenericModule.kvp"))
        raw = gen.get("App.Ports", "").strip()
        if raw:
            try:
                entries = json.loads(raw)
            except json.JSONDecodeError:
                print(f"  ! {name}: App.Ports is not valid JSON, skipping game ports",
                      file=sys.stderr)
                entries = []
            by_proto: dict[str, list[int]] = {}
            for e in entries:
                if e.get("Ref") in EXCLUDED_PORT_REFS:
                    continue
                proto = PROTO.get(e.get("Protocol"), "tcp_udp")
                port = int(e.get("Port", 0))
                span = max(1, int(e.get("Range", 1) or 1))
                if port:
                    by_proto.setdefault(proto, []).extend(range(port, port + span))
            for proto, ports in by_proto.items():
                for rng in merge_ranges(ports):
                    # Suffix only when an instance spans several protocols, so the
                    # common single-protocol case keeps the stable name "<inst> game".
                    kind = "game" if len(by_proto) == 1 else f"game-{proto}"
                    specs.append((kind, rng, proto))

    fm = read_kvp(os.path.join(base, "FileManagerPlugin.kvp"))
    if fm.get("SFTP.SFTPEnabled", "").strip().lower() == "true":
        sftp = fm.get("SFTP.SFTPPortNumber", "").strip()
        if sftp.isdigit():
            specs.append(("sftp", sftp, "tcp"))

    return specs


# --------------------------------------------------------------- UniFi client

def unifi(method: str, path: str = "", body: dict | None = None):
    url = f"{UNIFI_HOST}/proxy/network/api/s/{UNIFI_SITE}/rest/portforward{path}"
    res = _request(
        url, method,
        {"X-API-KEY": UNIFI_API_KEY, "Content-Type": "application/json",
         "Accept": "application/json"},
        body, insecure=True,
    )
    return (res or {}).get("data", [])


def load_streak() -> dict[str, int]:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: int(v) for k, v in data.get("stopped_streak", {}).items()}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def save_streak(streak: dict[str, int]) -> None:
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = f"{STATE_FILE}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"stopped_streak": streak}, fh)
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        # Non-fatal: degrades to in-memory debounce, which fails safe (a fresh
        # streak needs DEBOUNCE_POLLS readings before anything closes).
        print(f"  . could not persist state to {STATE_FILE}: {e}", file=sys.stderr)


def unifi_site_id(forwards: list[dict]) -> str:
    for f in forwards:
        if f.get("site_id"):
            return f["site_id"]
    raise RuntimeError("could not determine site_id from existing forwards")


# ------------------------------------------------------------------- reconcile

def desired_state(instances: list[dict], stopped_streak: dict[str, int]) -> dict[str, dict]:
    """name -> {port, proto, enabled} for every forward AMP implies."""
    want: dict[str, dict] = {}
    for inst in instances:
        name = inst.get("InstanceName", "")
        if not name or name in EXCLUDE_INSTANCES:
            continue

        state = inst.get("AppState", -1)
        running = state not in STOPPED_STATES

        # Debounce: only a *settled* stop closes a game port.
        streak = 0 if running else stopped_streak.get(name, 0) + 1
        stopped_streak[name] = streak
        game_enabled = running or streak < DEBOUNCE_POLLS

        # SFTP belongs to the *instance*, not the game application: AMP serves it
        # whenever the instance daemon is up, and you most want file access while
        # the game server is stopped. So it tracks Running, never AppState.
        sftp_enabled = bool(inst.get("Running")) and not inst.get("Suspended")

        label = STATE_NAMES.get(state, str(state))
        for kind, port, proto in instance_ports(name, inst.get("Module", "")):
            is_sftp = kind == "sftp"
            want[f"{MARKER} {name} {kind}"] = {
                "port": port,
                "proto": proto,
                "enabled": sftp_enabled if is_sftp else game_enabled,
                "state": f"instance {'up' if sftp_enabled else 'down'}" if is_sftp else label,
                "streak": streak,
            }
    return want


def build_doc(name: str, spec: dict, site_id: str) -> dict:
    return {
        "name": name,
        "enabled": spec["enabled"],
        "pfwd_interface": PFWD_INTERFACE,
        "proto": spec["proto"],
        "fwd": FWD_TARGET,
        "dst_port": spec["port"],
        "fwd_port": spec["port"],
        "destination_ip": "any",
        "destination_ips": [],
        "src_limiting_enabled": False,
        "site_id": site_id,
    }


def reconcile(dry_run: bool, stopped_streak: dict[str, int]) -> int:
    session = amp_login()
    instances = amp_instances(session)
    if not instances:
        print("! AMP returned no instances; refusing to reconcile", file=sys.stderr)
        return 1

    forwards = unifi("GET")
    site_id = unifi_site_id(forwards)

    owned = {f["name"]: f for f in forwards if f.get("name", "").startswith(MARKER)}
    foreign = [f for f in forwards if not f.get("name", "").startswith(MARKER)]

    # Foreign rules reserve their ports. A desired rule colliding with one is
    # skipped loudly -- never duplicated, never overwritten.
    reserved: dict[tuple[str, str], str] = {}
    for f in foreign:
        reserved[(str(f.get("dst_port")), str(f.get("proto")))] = f.get("name", "?")

    want = desired_state(instances, stopped_streak)
    if not dry_run:
        save_streak(stopped_streak)

    creates, updates, deletes, skips = [], [], [], []

    for name, spec in sorted(want.items()):
        cur = owned.get(name)
        if cur is None:
            clash = reserved.get((spec["port"], spec["proto"]))
            # tcp_udp overlaps both single-protocol rules, so check those too.
            if clash is None and spec["proto"] == "tcp_udp":
                clash = (reserved.get((spec["port"], "tcp"))
                         or reserved.get((spec["port"], "udp")))
            if clash is None:
                clash = reserved.get((spec["port"], "tcp_udp"))
            if clash:
                skips.append((name, spec, clash))
                continue
            creates.append((name, spec))
        else:
            diff = {}
            if bool(cur.get("enabled")) != spec["enabled"]:
                diff["enabled"] = spec["enabled"]
            if str(cur.get("dst_port")) != spec["port"]:
                diff["dst_port"] = spec["port"]
                diff["fwd_port"] = spec["port"]
            if str(cur.get("proto")) != spec["proto"]:
                diff["proto"] = spec["proto"]
            if str(cur.get("fwd")) != FWD_TARGET:
                diff["fwd"] = FWD_TARGET
            if diff:
                updates.append((name, cur, diff))

    for name, cur in sorted(owned.items()):
        if name not in want:
            deletes.append((name, cur))

    print(f"amp instances: {len(instances)} | desired: {len(want)} | "
          f"owned: {len(owned)} | foreign (untouched): {len(foreign)}")

    for name, spec, clash in skips:
        print(f"  ! SKIP {name} {spec['port']}/{spec['proto']} — port reserved by "
              f"foreign rule {clash!r}", file=sys.stderr)
    for name, spec in creates:
        pending = ""
        if spec["enabled"] and 0 < spec["streak"] < DEBOUNCE_POLLS and not name.endswith(" sftp"):
            pending = f", closes in {DEBOUNCE_POLLS - spec['streak']} more poll(s)"
        print(f"  + {name}  {spec['port']}/{spec['proto']}  "
              f"enabled={spec['enabled']} ({spec['state']}{pending})")
    for name, _cur, diff in updates:
        print(f"  ~ {name}  {diff}")
    for name, _cur in deletes:
        print(f"  - {name}")

    if not (creates or updates or deletes):
        print("  (converged)")

    if dry_run:
        return 0

    for name, spec in creates:
        try:
            unifi("POST", "", build_doc(name, spec, site_id))
            print(f"  + {name}")
        except urllib.error.HTTPError as e:
            print(f"  ! create {name}: {e.code} {e.read().decode()[:120]}", file=sys.stderr)

    for name, cur, diff in updates:
        try:
            unifi("PUT", f"/{cur['_id']}", {**cur, **diff})
            print(f"  ~ {name}")
        except urllib.error.HTTPError as e:
            print(f"  ! update {name}: {e.code} {e.read().decode()[:120]}", file=sys.stderr)

    for name, cur in deletes:
        try:
            unifi("DELETE", f"/{cur['_id']}")
            print(f"  - {name}")
        except urllib.error.HTTPError as e:
            print(f"  ! delete {name}: {e.code} {e.read().decode()[:120]}", file=sys.stderr)

    return 0


# ----------------------------------------------------------------- adoption

def adopt(dry_run: bool, map_path: str) -> int:
    """Rename pre-existing hand-made rules into ownership, so that migrating to
    this tool never closes a port. The map is site-specific, so it is supplied as
    a JSON file of {"<existing rule name>": "<instance> <kind>"} rather than
    baked in."""
    try:
        with open(map_path, encoding="utf-8") as fh:
            raw_map = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"could not read adopt map {map_path}: {e}", file=sys.stderr)
        return 2

    adoptions = {old: f"{MARKER} {new}" for old, new in raw_map.items()}
    forwards = unifi("GET")
    by_name = {f.get("name"): f for f in forwards}
    planned = [(old, new) for old, new in adoptions.items() if old in by_name]

    for old, new in planned:
        print(f"  ~ rename {old!r} -> {new!r}")
    for old in adoptions:
        if old not in by_name:
            print(f"  . not present, nothing to adopt: {old!r}")

    if dry_run:
        print("(dry run — nothing changed)")
        return 0

    for old, new in planned:
        cur = by_name[old]
        try:
            unifi("PUT", f"/{cur['_id']}", {**cur, "name": new})
            print(f"  ~ {old} -> {new}")
        except urllib.error.HTTPError as e:
            print(f"  ! rename {old}: {e.code} {e.read().decode()[:120]}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dry-run", action="store_true", help="print the diff, change nothing")
    ap.add_argument("--once", action="store_true", help="one pass, then exit")
    ap.add_argument("--interval", type=int, default=int(os.environ.get("INTERVAL", "60")))
    ap.add_argument("--adopt", metavar="MAP.json",
                    help="one-time: rename pre-existing rules listed in this JSON map")
    args = ap.parse_args()

    required = (("AMP_URL", AMP_URL), ("AMP_USER", AMP_USER), ("AMP_PASS", AMP_PASS),
                ("UNIFI_HOST", UNIFI_HOST), ("UNIFI_API_KEY", UNIFI_API_KEY),
                ("AMP_TARGET_IP", FWD_TARGET))
    missing = [n for n, v in required if not v]
    if missing:
        print(f"missing required env: {', '.join(missing)}", file=sys.stderr)
        return 2

    if args.adopt:
        return adopt(args.dry_run, args.adopt)

    stopped_streak = load_streak()

    if args.once or args.dry_run:
        return reconcile(args.dry_run, stopped_streak)

    while True:
        try:
            reconcile(False, stopped_streak)
        except Exception as e:  # keep the loop alive across transient failures
            print(f"! reconcile failed: {type(e).__name__}: {e}", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
