# netbox-monitor

Network auto-documentation service that keeps [NetBox](https://netbox.dev) continuously in
sync with reality. It runs alongside NetBox (not inside it) and talks to everything over
APIs:

| Module | What it does | Default interval |
|---|---|---|
| **dhcp** | Mirrors Technitium DHCP leases: dynamic leases become IPAddress records (deleted when the lease expires); reservations become full Devices | 60s |
| **dns** | Collates Technitium DNS zones with NetBox IPs: sets `dns_name`, reports drift | 5 min |
| **discovery** | Ping-sweeps every active NetBox prefix *outside* the DHCP scopes; responders become Devices with MAC, OUI manufacturer, reverse-DNS name | 15 min |
| **availability** | Pings discovered/reserved hosts (skipping any site's `exclude_prefixes`); unreachable > 10 min → tagged `stale` + status offline, auto-recovers when back | 60s |
| **proxmox** | Syncs PVE nodes, QEMU VMs and LXC containers (resources, interfaces, IPs via guest agent) into NetBox virtualization | 5 min |
| **lldp** | Crawls the switch fabric from `lldp-source` seeds (Cisco/Arista/Aruba/MikroTik/UniFi over SSH, or SNMP), auto-creates discovered switches, and documents links as cables | 30 min |
| **certs** | Probes TLS ports on every host with a primary IP; records expiry/issuer/CN, tags `cert-expiring` / `cert-expired` | daily |

Everything the service creates is tagged `managed:netbox-monitor` plus a source tag
(`src:dhcp`, `src:scan`, `src:proxmox`, `src:lldp`). **It never deletes or lifecycle-edits
records that don't carry its tags** — your hand-curated documentation is safe.

## Web UI (v2)

v2 ships a built-in web UI at **http://\<host\>:8899**:

- **First run** asks you to set a password (or pre-set `WEBUI_PASSWORD` in `.env`).
- **Settings**: NetBox URL + token (with a connection test), per-module **polling
  intervals** and enable switches, lifecycle rules, dry-run toggle, log level.
- **Sites**: define any number of sites — each pairs a **NetBox Site** (picked from
  the sites already in your NetBox, or created on the fly) with its own **Technitium
  instance**, **Proxmox instances**, and **discovery scanning scope** (prefix pickers
  populated live from NetBox). Every section has a Test button.
- **Dashboard**: per-module / per-site last-run status and **Run now** buttons.
- **Backup**: export/import the whole configuration, encrypted or redacted (see
  [Backup & restore](#backup--restore--moving-to-another-host)).
- **`/healthz`**: unauthenticated liveness JSON (version, schema, whether it's
  configured, uptime — no URLs or credentials) for container healthchecks.

Configuration edits apply immediately — the sync engine hot-reloads without a restart.
The live config persists in `data/settings.json` (keep the data volume!); `config.yaml`
is only imported on first start when no settings.json exists. **v1 configs migrate
automatically** into a single site.

## Quick start

Everything is configured in the **web UI** — no config files are required to start.
You need a Linux host with Docker, ideally one that can reach every VLAN you want to
scan (ARP-based MAC/vendor enrichment only works for L2-adjacent subnets).

### Option A — straight from the published image (no clone)

Create one file, `docker-compose.yml`:

```yaml
services:
  netbox-monitor:
    image: ghcr.io/sremich/netbox-monitor:latest
    restart: unless-stopped
    network_mode: host          # web UI on http://<host>:8899, and LAN access for discovery
    cap_add: [NET_RAW, NET_ADMIN]  # raw ICMP for ping discovery
    # environment:
    #   - WEBUI_PASSWORD=change-me   # optional: skip the first-run password prompt
    volumes:
      - netbox-monitor-data:/app/data
volumes:
  netbox-monitor-data:
```

Then:

```sh
docker compose up -d
```

Or a one-liner with no compose file at all:

```sh
docker run -d --name netbox-monitor --restart unless-stopped \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v netbox-monitor-data:/app/data \
  ghcr.io/sremich/netbox-monitor:latest
```

### Option B — clone the repo

```sh
git clone https://github.com/sremich/netbox-monitor
cd netbox-monitor
docker compose up -d        # pulls the image; no .env or config.yaml needed
```

(To build the image from source instead of pulling: `docker compose build` first, or
add `build: .` under the service.)

### First run

1. Open **http://\<host\>:8899** and set an admin password (or pre-set `WEBUI_PASSWORD`).
2. **Settings → NetBox**: enter your NetBox URL + an API token (Admin → API Tokens, write
   access) and hit *Test*.
3. **Sites → Add site**: pick/create a NetBox Site and add that site's Technitium
   instance, Proxmox instance(s), and scan scope — each section has a *Test* button.
   - *Technitium* token: `curl "http://<dns>:5380/api/user/createToken?user=admin&pass=...&tokenName=netbox-monitor"`
   - *Proxmox* token: Datacenter → Permissions → API Tokens, e.g. `monitor@pve` /
     `netbox-monitor`, with the `PVEAuditor` role on `/`.
4. Toggle modules on and adjust intervals under **Settings**. Turn on **dry-run** first
   if you want to watch what it *would* write before it writes anything.

Config edits apply immediately (the engine hot-reloads). Everything persists in the
`netbox-monitor-data` volume — **keep that volume** across upgrades. Upgrade with
`docker compose pull && docker compose up -d`.

> Optional: a `.env` file (see `.env.example`) can pre-seed `WEBUI_PASSWORD` and tokens,
> and `config.yaml` (see `config.example.yaml`) can seed the whole config on first start
> — both are optional and the compose file works without them.

### Headless / CLI

The image also runs a single module once and exits (useful for cron or testing):

```sh
docker compose run --rm netbox-monitor --once dhcp --dry-run
```

Modules: `dhcp`, `dns`, `discovery`, `availability`, `proxmox`, `lldp`, `certs`.

### LLDP topology crawl (optional)

The LLDP module maps your physical switch fabric and draws it as NetBox cables. It
**crawls**: from a few seed switches it reads LLDP neighbors, follows switch-to-switch
links, auto-creates any switch it finds, authenticates to it, and continues — so you
only have to seed a couple of switches to map the whole fabric.

1. **Seed** a switch or two: tag them `lldp-source` in NetBox, give each a primary IP,
   assign them to a Site, and set their platform (`cisco`, `arista`, `aruba`, `mikrotik`,
   `unifi`, … — used to pick the driver; unknown platforms are auto-detected).
2. **Site credentials** (site page → LLDP topology): the SSH user/password and/or SNMP
   community for that site's switches — tried first against everything at the site.
3. **Global credential profiles** (Settings → LLDP topology crawl): a list of
   name + driver + SSH/SNMP secrets tried, in order, against every switch the crawl
   discovers. Also set the crawl toggle and `max switches`/`max depth` bounds here.
4. Enable LLDP for the site and turn crawl on.

Supported drivers: **Cisco** IOS/NX-OS, **Arista** EOS, **Aruba** (CX + ArubaOS-Switch),
**MikroTik** RouterOS, **UniFi** (all over SSH), and **SNMP** LLDP-MIB for anything else
with SNMP enabled. Discovered switches become NetBox devices (role **Switch**, tagged
`src:lldp`) with their management IP; a working driver+credential is cached per switch so
later runs skip the trial loop.

**One box, one device.** Each polled switch also reports its *own* MAC addresses
(chassis/bridge/interface), which the crawl records on the device. A switch reachable at
several management IPs — say a seed documented at one address while its LLDP TLVs
advertise another — is recognised by those MACs and folded into a **single** device
instead of being documented twice: the duplicate's IPs move onto the surviving device and
the managed copy is deleted. Human-created devices always win a merge and are never
deleted; if the duplicate holds any record the tool doesn't manage, the merge is refused. Only neighbors matching a known switch vendor are crawled,
so hosts that merely advertise a bridge (e.g. Linux/Proxmox nodes) are never touched.

Optional per-switch credentials: install the
[netbox-secrets](https://github.com/Onemind-Services-LLC/netbox-secrets) plugin, point
`lldp.secrets_private_key` at your RSA key, and attach secrets to switch devices
(role `snmp` → community; role `ssh` → name = username, plaintext = password). Plugin
credentials take precedence.

> **Switch ACLs**: many switches restrict SSH/SNMP to a management subnet (Cisco vty
> `access-class`). Permit the host running netbox-monitor, or the crawl will log those
> switches as unreachable (it stops after one connection-reset rather than retrying).

**A switch isn't being polled?** The dashboard status names each failed host with the
drivers tried and the error each returned (e.g. `10.0.0.5: cisco/TimeoutError`); the log
carries the full messages. Two common causes:

- **SSH doesn't work on that model.** Some switches (e.g. Cisco Small Business SG300)
  only offer crypto too old to negotiate, but answer **SNMP** fine. Set an SNMP community
  in the site's LLDP settings or a credential profile — with no community configured the
  SNMP driver is never tried and the switch just fails every SSH attempt.
- **The seed is on the wrong site.** Seeds are looked up *per site*, so an
  `lldp-source` switch whose NetBox Site isn't one of your configured sites is never
  polled — easy to miss after moving sites. The log flags these at startup
  (*"lldp seed switch is at a site with no LLDP-enabled config"*); fix it by moving the
  device to the right Site in NetBox.

**Protecting production gear.** Two safeguards keep the crawl from ever hammering a
router/firewall:

- **Document-only exclusion list** (Settings → LLDP topology crawl → *Never authenticate
  these hosts*): listed IPs are drawn into the topology from neighbor data but the tool
  **never opens an SSH/SNMP session to them**. Use it for production routers.
- **No credential spraying**: when a switch's vendor is known (platform or LLDP
  description) only that one driver's login is tried, and there's a hard per-host cap
  (`max_auth_attempts`, default 4) so a device is never hit with a barrage of logins.

## Cleanup / migrating sites

The **Cleanup** page (top nav) inventories every object this service created — devices,
VMs, IPs, cables, all tagged `managed:netbox-monitor` — grouped by site, source, and
staleness. You can then bulk-delete a selection (by site, source, "only stale", or "not
seen in N days"), with a **Preview (count only)** step and an explicit confirm before
anything is removed. Human-created objects are never touched. Optionally tick *Re-run
discovery afterwards* to recreate hosts fresh on the current site.

Two things to know when **moving everything to a different NetBox site**:

- The sync **auto-migrates** a device to the site that re-discovers it *when it's matched
  by MAC* — so MAC-known hosts re-home themselves. Hosts discovered by ping only (no ARP
  MAC) are matched by name and stay put; use Cleanup to remove them and let the next
  discovery recreate them on the right site.
- Discovery only scans prefixes **scoped to a site's NetBox Site** — unless you run a
  **single** configured site, in which case it scans all active prefixes. So for a
  multi-site setup, scope your prefixes to each NetBox Site (or set per-site
  include-prefixes); the dashboard flags a site that has nothing to scan.

## Backup & restore / moving to another host

The **Backup** page exports this instance's whole configuration — sites, NetBox /
Technitium / Proxmox tokens, switch credentials, module settings — as a single JSON
file, and imports it back. Two modes:

- **Encrypted** (passphrase) — contains every credential. This is the one to use for
  a real backup or to move a setup to another host.
- **Redacted** (no passphrase) — every secret replaced by `__REDACTED__`. Safe to
  diff, keep in git, or attach to a bug report. Importing it **keeps the secrets the
  target already has** rather than blanking them; anything it can't match is left
  empty and reported.

> ⚠️ An encrypted export contains every token and password the instance holds. The
> passphrase is the only thing protecting it, and **there is no recovery if you lose
> it** — the file is useless without it.

Your **web UI password is never exported**. Importing therefore can't lock you out or
change how you log in, and a leaked export can't be used to forge sessions against the
instance it came from. On import the previous config is saved to `settings.json.bak`,
and the sync engine picks up the new one within a couple of seconds — no restart.

**Restore on first boot** (a fresh container comes up fully configured, no clicking):

```yaml
    volumes:
      - ./netbox-monitor-config.json:/app/restore.json:ro
    environment:
      - NBM_RESTORE_FILE=/app/restore.json
      - NBM_RESTORE_PASSPHRASE_FILE=/run/secrets/nbm_restore_pw  # keeps it out of `docker inspect`
```

Only used when `data/settings.json` doesn't exist, so it never clobbers a live config.
A wrong passphrase logs an error and starts unconfigured rather than crash-looping —
delete `data/settings.json` and restart to retry, or set `NBM_RESTORE_STRICT=1` to fail
hard instead. Since the export carries no password, `WEBUI_PASSWORD` / the setup page
still apply.

**Upgrades are safe:** every config records the schema it was written at, and older
ones are migrated on load. Each release is tested against real configs and exports from
previous releases, so an old backup keeps working. A config written by a *newer*
version is refused rather than silently downgraded.

## NetBox objects it maintains

- Tags: `managed:netbox-monitor`, `src:*`, `stale`, `cert-expiring`, `cert-expired`
- Custom fields: `last_seen`, `discovered_mac`, `oui_vendor` (IP/device),
  `dhcp_scope` (prefix), `cert_expiry`/`cert_issuer`/`cert_cn` (device/VM)
- Device roles: `Discovered`, `Hypervisor`, `Switch`

## Development

```sh
pip install -e ".[dev]"
ruff check . && pytest
```

### Releasing

The version lives in **one** place: `src/netbox_monitor/__init__.py` (pyproject reads
it via hatchling). Bump it, add the config-export golden fixture for the new version
(`pytest` tells you if it's missing, and how to generate it), then tag `vX.Y.Z` — CI
refuses to publish an image whose tag disagrees with the code. See `CLAUDE.md` for the
config-compatibility rules that keep old backups importable.

## Backlog / future ideas

- **Notification system** (planned next): unified alerts via ntfy/Discord/webhooks for
  cert expiry (replacing tag-only warnings), stale transitions, and rogue devices.
- Rogue-device alerting: flag never-before-seen MACs from discovery.
- IP conflict detection: same IP answering with different MACs across scans.
- Service discovery: light TCP probe → NetBox Service objects.
- Prefix utilization + DNS drift reports as scheduled journal entries.
- Config backup integration (Oxidized) linked from device pages.
