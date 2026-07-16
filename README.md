# netbox-monitor

Network auto-documentation service that keeps [NetBox](https://netbox.dev) continuously in
sync with reality. It runs alongside NetBox (not inside it) and talks to everything over
APIs:

| Module | What it does | Default interval |
|---|---|---|
| **dhcp** | Mirrors Technitium DHCP leases: dynamic leases become IPAddress records (deleted when the lease expires); reservations become full Devices | 60s |
| **dns** | Collates Technitium DNS zones with NetBox IPs: sets `dns_name`, reports drift | 5 min |
| **discovery** | Ping-sweeps every active NetBox prefix *outside* the DHCP scopes; responders become Devices with MAC, OUI manufacturer, reverse-DNS name | 15 min |
| **availability** | Pings all discovered/reserved hosts; unreachable > 10 min → tagged `stale` + status offline, auto-recovers when back | 60s |
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

Configuration edits apply immediately — the sync engine hot-reloads without a restart.
The live config persists in `data/settings.json` (keep the data volume!); `config.yaml`
is only imported on first start when no settings.json exists. **v1 configs migrate
automatically** into a single site.

## Setup

### 1. Tokens

- **NetBox**: create an API token (Admin → API Tokens) with write access.
- **Technitium**: create a permanent API token:
  `curl "http://10.0.0.2:5380/api/user/createToken?user=admin&pass=...&tokenName=netbox-monitor"`
- **Proxmox**: create an API token (Datacenter → Permissions → API Tokens), e.g. user
  `monitor@pve`, token `netbox-monitor`, with the `PVEAuditor` role on `/`.

### 2. Configure

```sh
cp config.example.yaml config.yaml
cp .env.example .env      # fill in tokens
```

### 3. First run — dry-run

Set `dry_run: true` in `config.yaml` (or pass `--dry-run`) and watch the logs: every
NetBox write is logged but not executed. Run a single module with
`netbox-monitor --once dhcp` (also: `dns`, `discovery`, `availability`, `proxmox`,
`lldp`, `certs`).

### 4. Deploy (Docker on Linux)

```sh
docker compose up -d
```

The compose file uses **host networking** + `NET_RAW` so ICMP sweeps and ARP reads work.
Run it on a host that can reach every VLAN you want scanned (MAC harvesting via ARP only
works for L2-adjacent subnets). Enable modules one at a time in `config.yaml` if you
prefer a gradual rollout.

Images are published to `ghcr.io/sremich/netbox-monitor` by CI on every push to `main`;
deployment is `docker compose pull && docker compose up -d`.

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
later runs skip the trial loop. Only neighbors matching a known switch vendor are crawled,
so hosts that merely advertise a bridge (e.g. Linux/Proxmox nodes) are never touched.

Optional per-switch credentials: install the
[netbox-secrets](https://github.com/Onemind-Services-LLC/netbox-secrets) plugin, point
`lldp.secrets_private_key` at your RSA key, and attach secrets to switch devices
(role `snmp` → community; role `ssh` → name = username, plaintext = password). Plugin
credentials take precedence.

> **Switch ACLs**: many switches restrict SSH/SNMP to a management subnet (Cisco vty
> `access-class`). Permit the host running netbox-monitor, or the crawl will log those
> switches as unreachable (it stops after one connection-reset rather than retrying).

**Protecting production gear.** Two safeguards keep the crawl from ever hammering a
router/firewall:

- **Document-only exclusion list** (Settings → LLDP topology crawl → *Never authenticate
  these hosts*): listed IPs are drawn into the topology from neighbor data but the tool
  **never opens an SSH/SNMP session to them**. Use it for production routers.
- **No credential spraying**: when a switch's vendor is known (platform or LLDP
  description) only that one driver's login is tried, and there's a hard per-host cap
  (`max_auth_attempts`, default 4) so a device is never hit with a barrage of logins.

## NetBox objects it maintains

- Tags: `managed:netbox-monitor`, `src:*`, `stale`, `cert-expiring`, `cert-expired`
- Custom fields: `last_seen`, `discovered_mac`, `oui_vendor` (IP/device),
  `dhcp_scope` (prefix), `cert_expiry`/`cert_issuer`/`cert_cn` (device/VM)
- Device roles: `Discovered`, `Hypervisor`

## Development

```sh
pip install -e ".[dev]"
ruff check . && pytest
```

## Backlog / future ideas

- **Notification system** (planned next): unified alerts via ntfy/Discord/webhooks for
  cert expiry (replacing tag-only warnings), stale transitions, and rogue devices.
- Rogue-device alerting: flag never-before-seen MACs from discovery.
- IP conflict detection: same IP answering with different MACs across scans.
- Service discovery: light TCP probe → NetBox Service objects.
- Prefix utilization + DNS drift reports as scheduled journal entries.
- Config backup integration (Oxidized) linked from device pages.
