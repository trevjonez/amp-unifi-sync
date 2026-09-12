# amp-unifi-sync

Reconciles UniFi (UDM) port forwards against CubeCoders AMP instance state, so the
forward list is a *derived* artifact instead of hand-maintained state. Adding a game
server in AMP stops being a two-place edit.

Runs as a container on the Unraid box that hosts AMP. See `docs/amp-unifi-sync.md` in
the `home-network` repo for the deployment and runbook.

## Ownership — it cannot clobber your hand-made rules

Every forward the tool creates is named with a marker prefix (default `[amp-sync]`).

| Set | Definition | Tool behaviour |
|---|---|---|
| **owned** | `name` starts with the marker | the only rules ever POSTed / PUT / DELETEd |
| **foreign** | everything else | read, never written; their `(port, proto)` is **reserved** |
| **desired** | computed from AMP | a rule colliding with a reserved port is **skipped with a warning** |

The delete path filters on the marker *before* diffing, so a bug in desired-state
computation can at worst remove rules this tool created. It is structurally incapable
of modifying a hand-managed forward.

## Where the data comes from

- **State** — AMP API, `ADSModule/GetInstances` → `AppState`. The AMP CLI reports only
  whether the *instance daemon* is up, never the application, so the API is the only
  usable source.
- **Ports** — the instance `.kvp` files on disk, via a read-only bind mount. The API's
  `ApplicationEndpoints` field is protocol-blind and lists only the primary port (it
  omits, for example, Valheim's Steam query port 2457), so it cannot be used.

Game ports come from `GenericModule.kvp` → `App.Ports` (or `MinecraftModule.kvp` →
`Minecraft.PortNumber`); RCON refs (`RCONPort`, `RemoteAdminPort`) are always excluded.

## Two different state signals

- **Game ports** follow `AppState`, with a debounce: a stopped reading must persist
  for `DEBOUNCE_POLLS` consecutive polls before the port closes. This exists because a
  crash-looping server cycles `Ready → Stopping → Starting` every couple of minutes,
  and without it the UDM config would be rewritten continuously.
  `AppState 50` (Sleeping) counts as **running** — that is wake-on-connect idle mode,
  and closing the port would make the server unable to ever wake.
- **SFTP ports** follow the *instance* (`Running`), not the application. AMP serves
  SFTP whenever the instance daemon is up, and file access is most wanted precisely
  when the game server is stopped.

## Usage

```
sync.py --dry-run   # print the diff, change nothing
sync.py --once      # one reconcile pass, then exit
sync.py             # loop at --interval (default 60s)
sync.py --adopt map.json   # one-time: rename pre-existing rules into ownership
```

## Tests

```
python3 -m unittest -v      # stdlib only, no dependencies
```

Covers the anti-clobber collision guard (including combined `"2226,2230"` and
range rules), kvp port parsing against real AMP fixtures, RCON exclusion, and the
debounce/crash-loop/sleep state machine. CI runs them before the image is built.

## Configuration (environment)

| Var | Default | Notes |
|---|---|---|
| `AMP_URL` | — | **required**; the ADS instance, e.g. `http://10.0.0.5:8080` |
| `AMP_USER` / `AMP_PASS` | — | **required**; a dedicated AMP service account |
| `AMP_INSTANCES_DIR` | `/amp` | read-only mount of AMP's `instances/` |
| `UNIFI_HOST` | — | **required**; the UDM, e.g. `https://10.0.0.1` |
| `UNIFI_API_KEY` | — | **required**; `X-API-KEY`, legacy Network API |
| `UNIFI_SITE` | `default` | |
| `AMP_TARGET_IP` | — | **required**; forward destination (AMP's own address) |
| `PFWD_INTERFACE` | `wan` | `wan` = primary WAN only; `both`/`all` = every WAN |
| `MARKER` | `[amp-sync]` | ownership prefix — changing it orphans existing rules |
| `DEBOUNCE_POLLS` | `3` | consecutive stopped polls before a game port closes |
| `EXCLUDE_INSTANCES` | `Main` | ADS controller; keeps its SFTP port off the WAN |
| `STATE_FILE` | `/var/lib/amp-unifi-sync/state.json` | debounce counters; mount a volume |

The UDM serves a self-signed certificate, so UniFi calls skip verification (the
`curl -k` equivalent). AMP calls do not.

## Why polling rather than AMP's event triggers

AMP does support event-driven triggers (`GenericApp_StateChanged` as a schedulable
event, with `MakeGETRequest` as an action). Polling is still preferred here: triggers
are per-instance config living in a binary `datastore.dat`, so they can't be
version-controlled or reviewed in a diff; they wouldn't remove the need for the
debounce; and polling is stateless and self-healing, so a missed event can't desync
the world and a restarted container reconverges on its first pass.
