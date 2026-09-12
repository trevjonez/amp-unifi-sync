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
import html
import http.server
import json
import os
import re
import ssl
import sys
import threading
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

# Read-only status GUI. Served in loop mode only; 0 disables it.
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8099"))
HTTP_BIND = os.environ.get("HTTP_BIND", "0.0.0.0")

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


# ------------------------------------------------------------------ redaction

REDACTED = "«redacted»"
# Credentials in a URL's userinfo (http://user:pass@host) -- an AMP_URL written
# that way would otherwise reach the log through an exception message.
_USERINFO = re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@", re.I)
# Anything that looks like a secret-bearing key in JSON or a query string.
_KEYED = re.compile(
    r"([\"']?(?:password|passwd|pass|token|api[_-]?key|sessionid|secret)"
    r"[\"']?\s*[:=]\s*)([\"']?)([^\"'&,}\s]+)", re.I)
# Auth headers carry a scheme before the token ("Bearer abc"), so redacting only
# the first word after the colon would leave the credential itself in place.
_AUTH_HEADER = re.compile(r"(authorization\s*[:=]\s*)(.+)", re.I)


def scrub(text: object) -> str:
    """Remove credentials from anything about to be logged or served.

    Defence in depth: the report is built from an explicit field allowlist and
    never carries secrets, but error text is quoted from remote responses and
    exception messages, which we do not control.
    """
    out = str(text)
    for secret in (AMP_PASS, UNIFI_API_KEY):
        # Length guard: a 1-2 char secret would redact half the page.
        if secret and len(secret) >= 6:
            out = out.replace(secret, REDACTED)
    out = _USERINFO.sub(rf"\1{REDACTED}@", out)
    out = _KEYED.sub(rf"\1\g<2>{REDACTED}", out)
    out = _AUTH_HEADER.sub(rf"\1{REDACTED}", out)
    return out


def say(msg: object, err: bool = False) -> None:
    print(scrub(msg), file=sys.stderr if err else sys.stdout)


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


def instance_game(name: str, module: str) -> str:
    """Human label for what an instance runs, for the status page."""
    base = os.path.join(AMP_INSTANCES_DIR, name)
    if "Minecraft" in module:
        mc = read_kvp(os.path.join(base, "MinecraftModule.kvp"))
        variant = mc.get("Minecraft.ServerType", "").strip()
        return f"Minecraft ({variant})" if variant else "Minecraft"
    gen = read_kvp(os.path.join(base, "GenericModule.kvp"))
    return gen.get("Meta.DisplayName", "").strip() or module or "unknown"


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
        say(f"  . could not persist state to {STATE_FILE}: {e}", err=True)


def expand_ports(spec: str) -> set[int]:
    """'2226,2230' -> {2226,2230};  '2456-2457' -> {2456,2457}

    UniFi stores dst_port as a free-form string that may combine both forms, so a
    reservation check that compares strings would miss a foreign rule covering
    several ports and happily create a duplicate forward on top of it.
    """
    out: set[int] = set()
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        lo, sep, hi = part.partition("-")
        try:
            if sep:
                out.update(range(int(lo), int(hi) + 1))
            else:
                out.add(int(lo))
        except ValueError:
            continue
    return out


def protos_overlap(a: str, b: str) -> bool:
    return a == b or "tcp_udp" in (a, b)


def build_reservations(foreign: list[dict]) -> list[tuple[set[int], str, str]]:
    """Foreign rules reserve every port they cover, expanded, so a combined rule
    such as '2226,2230' blocks each port individually."""
    return [
        (expand_ports(f.get("dst_port", "")), str(f.get("proto")), f.get("name", "?"))
        for f in foreign
    ]


def find_collision(reserved: list[tuple[set[int], str, str]],
                   port_spec: str, proto: str) -> str | None:
    """Name of the foreign rule blocking this (ports, proto), or None."""
    wanted = expand_ports(port_spec)
    for ports, fproto, fname in reserved:
        if wanted & ports and protos_overlap(proto, fproto):
            return fname
    return None


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
        module = inst.get("Module", "")
        game = instance_game(name, module)
        for kind, port, proto in instance_ports(name, module):
            is_sftp = kind == "sftp"
            want[f"{MARKER} {name} {kind}"] = {
                "port": port,
                "proto": proto,
                "enabled": sftp_enabled if is_sftp else game_enabled,
                "state": f"instance {'up' if sftp_enabled else 'down'}" if is_sftp else label,
                "streak": streak,
                # Carried for the status page so it can group and explain.
                "instance": name,
                "kind": kind,
                "game": game,
                "app_state": label,
                "instance_up": sftp_enabled,
            }
    return want


def explain(spec: dict, blocked_by: str | None, error: str | None) -> tuple[str, str]:
    """(status, human reason) for one desired forward — the 'why' the GUI shows."""
    if error:
        return "error", error
    if blocked_by:
        return "blocked", (f"port {spec['port']}/{spec['proto']} is already used by "
                           f"“{blocked_by}”, a rule this tool does not manage")
    if spec["kind"] == "sftp":
        if spec["enabled"]:
            return "open", "instance is up"
        return "closed", "instance is not running"
    if spec["enabled"]:
        streak = spec.get("streak", 0)
        if streak:
            left = DEBOUNCE_POLLS - streak
            return "open", (f"server is {spec['app_state']} — closing in {left} "
                            f"more poll{'s' if left != 1 else ''}")
        if spec["app_state"] == "Sleeping":
            return "open", "server is asleep and wakes on connect, so the port stays open"
        return "open", f"server is {spec['app_state']}"
    return "closed", f"server is {spec['app_state']}"


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

    # A desired rule colliding with a foreign reservation is skipped loudly --
    # never duplicated, never overwritten.
    reserved = build_reservations(foreign)

    want = desired_state(instances, stopped_streak)
    if not dry_run:
        save_streak(stopped_streak)

    creates, updates, deletes, skips = [], [], [], []

    for name, spec in sorted(want.items()):
        cur = owned.get(name)
        if cur is None:
            clash = find_collision(reserved, spec["port"], spec["proto"])
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

    blocked = {name: clash for name, _spec, clash in skips}
    errors: dict[str, str] = {}

    if dry_run:
        publish_report(instances, want, blocked, errors, len(foreign))
        return 0

    for name, spec in creates:
        try:
            unifi("POST", "", build_doc(name, spec, site_id))
            print(f"  + {name}")
        except urllib.error.HTTPError as e:
            errors[name] = f"create failed: HTTP {e.code}"
            say(f"  ! create {name}: {e.code} {e.read().decode()[:120]}", err=True)

    for name, cur, diff in updates:
        try:
            unifi("PUT", f"/{cur['_id']}", {**cur, **diff})
            print(f"  ~ {name}")
        except urllib.error.HTTPError as e:
            errors[name] = f"update failed: HTTP {e.code}"
            say(f"  ! update {name}: {e.code} {e.read().decode()[:120]}", err=True)

    for name, cur in deletes:
        try:
            unifi("DELETE", f"/{cur['_id']}")
            print(f"  - {name}")
        except urllib.error.HTTPError as e:
            errors[name] = f"delete failed: HTTP {e.code}"
            say(f"  ! delete {name}: {e.code} {e.read().decode()[:120]}", err=True)

    publish_report(instances, want, blocked, errors, len(foreign))
    return 0


# ------------------------------------------------------------- status reporting

_REPORT: dict | None = None
_REPORT_LOCK = threading.Lock()

STATUS_ORDER = {"error": 0, "blocked": 1, "closed": 2, "open": 3}


def build_report(instances: list[dict], want: dict[str, dict], blocked: dict[str, str],
                 errors: dict[str, str], foreign_count: int) -> dict:
    """Structured view of the last pass. Shared by the text log and the web GUI so
    they can never disagree about why a forward is missing."""
    by_instance: dict[str, dict] = {}

    for inst in instances:
        name = inst.get("InstanceName", "")
        if not name:
            continue
        module = inst.get("Module", "")
        excluded = name in EXCLUDE_INSTANCES
        by_instance[name] = {
            "name": name,
            "game": instance_game(name, module) if not excluded else "AMP controller",
            "module": module,
            "app_state": STATE_NAMES.get(inst.get("AppState", -1), str(inst.get("AppState"))),
            "instance_up": bool(inst.get("Running")) and not inst.get("Suspended"),
            "excluded": excluded,
            "note": "excluded from forwarding by configuration" if excluded else "",
            "rules": [],
        }

    for rule_name, spec in sorted(want.items()):
        status, reason = explain(spec, blocked.get(rule_name), errors.get(rule_name))
        row = by_instance.setdefault(spec["instance"], {
            "name": spec["instance"], "game": spec.get("game", ""), "module": "",
            "app_state": spec.get("app_state", ""), "instance_up": True,
            "excluded": False, "note": "", "rules": [],
        })
        row["rules"].append({
            "name": rule_name, "kind": spec["kind"], "port": spec["port"],
            "proto": spec["proto"], "status": status, "reason": reason,
        })

    for row in by_instance.values():
        row["rules"].sort(key=lambda r: (r["kind"] != "game", r["port"]))
        if not row["rules"] and not row["excluded"]:
            row["note"] = "no forwardable ports declared by this instance"

    counts: dict[str, int] = {}
    for row in by_instance.values():
        for r in row["rules"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

    ordered = sorted(
        by_instance.values(),
        key=lambda row: (row["excluded"],
                         min((STATUS_ORDER.get(r["status"], 9) for r in row["rules"]),
                             default=9),
                         row["name"].lower()),
    )
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "generated_epoch": time.time(),
        "marker": MARKER,
        "target": FWD_TARGET,
        "foreign_count": foreign_count,
        "counts": counts,
        "instances": ordered,
    }


def publish_report(instances, want, blocked, errors, foreign_count) -> None:
    global _REPORT
    report = build_report(instances, want, blocked, errors, foreign_count)
    with _REPORT_LOCK:
        _REPORT = report


BADGE = {"open": "ok", "closed": "off", "blocked": "warn", "error": "err"}

PAGE_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171a;--muted:#5b6570;--line:#e3e6ea;
--ok:#0f7b43;--off:#6b7280;--warn:#a8600a;--err:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1c2024;--fg:#e7eaee;
--muted:#9aa4af;--line:#2b3138;--ok:#4ade80;--off:#9aa4af;--warn:#fbbf24;--err:#f87171}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:8px 14px;min-width:92px}
.tile b{display:block;font-size:20px;line-height:1.2}
.tile span{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 16px;margin-bottom:12px}
.card.dim{opacity:.6}
.hdr{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline;margin-bottom:10px}
.hdr h2{font-size:15px;margin:0}
.hdr .game{color:var(--muted);font-size:13px}
.hdr .state{margin-left:auto;color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse}
td{padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
tr:first-child td{border-top:0}
td.port{white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;width:1%}
td.kind{color:var(--muted);width:1%;white-space:nowrap}
td.reason{color:var(--muted)}
.badge{display:inline-block;min-width:64px;text-align:center;padding:2px 8px;
border-radius:999px;font-size:12px;font-weight:600;border:1px solid currentColor}
.ok{color:var(--ok)} .off{color:var(--off)} .warn{color:var(--warn)} .err{color:var(--err)}
.note{color:var(--muted);font-size:13px;font-style:italic}
footer{color:var(--muted);font-size:12px;margin-top:24px;text-align:center}
.scroll{overflow-x:auto}
"""


def render_html(report: dict | None) -> str:
    esc = html.escape
    if report is None:
        return ("<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5>"
                f"<title>AMP port forwards</title><style>{PAGE_CSS}</style>"
                "<div class=wrap><h1>AMP port forwards</h1>"
                "<p class=sub>Waiting for the first reconcile pass…</p></div>")

    c = report["counts"]
    tiles = "".join(
        f'<div class="tile"><b class="{BADGE[k]}">{c.get(k,0)}</b><span>{k}</span></div>'
        for k in ("open", "closed", "blocked", "error") if c.get(k)
    ) or '<div class="tile"><b>0</b><span>rules</span></div>'

    cards = []
    for row in report["instances"]:
        rules = "".join(
            f'<tr><td class="port">{esc(r["port"])}/{esc(r["proto"])}</td>'
            f'<td class="kind">{esc(r["kind"])}</td>'
            f'<td><span class="badge {BADGE[r["status"]]}">{r["status"]}</span></td>'
            f'<td class="reason">{esc(r["reason"])}</td></tr>'
            for r in row["rules"]
        )
        body = (f'<div class="scroll"><table>{rules}</table></div>' if rules
                else f'<p class="note">{esc(row["note"] or "nothing to forward")}</p>')
        cards.append(
            f'<div class="card{" dim" if row["excluded"] or not row["rules"] else ""}">'
            f'<div class="hdr"><h2>{esc(row["name"])}</h2>'
            f'<span class="game">{esc(row["game"])}</span>'
            f'<span class="state">{esc(row["app_state"])}</span></div>{body}</div>'
        )

    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        '<meta http-equiv=refresh content=30>'
        "<title>AMP port forwards</title>"
        f"<style>{PAGE_CSS}</style></head><body><div class=wrap>"
        "<h1>AMP port forwards</h1>"
        f'<p class="sub">Forwards to {esc(report["target"])}, reconciled from AMP instance '
        f'state. {report["foreign_count"]} unmanaged rule(s) on the gateway are left '
        f'untouched.</p>{tiles}{"".join(cards)}'
        f'<footer>last pass {esc(report["generated"])} · rules named '
        f'<code>{esc(report["marker"])}</code> · read-only</footer>'
        "</div></body></html>"
    )


def start_http_server(port: int, bind: str, interval: int) -> None:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            with _REPORT_LOCK:
                report = _REPORT
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if path == "/":
                self._send(200, scrub(render_html(report)).encode(),
                       "text/html; charset=utf-8")
            elif path == "/api/status":
                self._send(200, scrub(json.dumps(report or {}, indent=2)).encode(),
                           "application/json")
            elif path == "/healthz":
                # Stale if several passes have been missed -- the reconciler is wedged.
                age = time.time() - report["generated_epoch"] if report else None
                ok = age is not None and age < max(interval * 5, 300)
                self._send(200 if ok else 503,
                           json.dumps({"ok": ok, "age_seconds": age}).encode(),
                           "application/json")
            else:
                self._send(404, b"not found\n", "text/plain")

        def log_message(self, *_args):
            pass  # the reconcile log is the useful one; access logs only add noise

    srv = http.server.ThreadingHTTPServer((bind, port), Handler)
    threading.Thread(target=srv.serve_forever, name="http", daemon=True).start()
    print(f"status GUI on http://{bind}:{port}/ (read-only)")


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
        say(f"could not read adopt map {map_path}: {e}", err=True)
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
            say(f"  ! rename {old}: {e.code} {e.read().decode()[:120]}", err=True)
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

    if HTTP_PORT:
        start_http_server(HTTP_PORT, HTTP_BIND, args.interval)

    while True:
        try:
            reconcile(False, stopped_streak)
        except Exception as e:  # keep the loop alive across transient failures
            say(f"! reconcile failed: {type(e).__name__}: {e}", err=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
