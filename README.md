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
| **lldp** | Polls switches tagged `lldp-source` (SNMP, or SSH+lldpd for UniFi) and documents topology as cables; credentials come from the netbox-secrets plugin | 30 min |
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

### LLDP topology (optional)

1. Install the [netbox-secrets](https://github.com/Onemind-Services-LLC/netbox-secrets)
   plugin in NetBox and generate an RSA key pair for your API user; mount the private key
   into the container and point `lldp.secrets_private_key` at it.
2. Attach secrets to each switch device: role `snmp` (plaintext = community string) or
   role `ssh` (secret name = username, plaintext = password, used for UniFi).
3. In NetBox, tag the switches `lldp-source`, give them a primary IP, and set their
   platform (`unifi` platforms use SSH+lldpd; everything else SNMP).
4. Set `lldp.enabled: true`.

No netbox-secrets? Use `lldp.fallback_creds` in the config instead.

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
