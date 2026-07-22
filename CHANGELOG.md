# Changelog

All notable changes to netbox-monitor. Versions correspond to git tags and
[GitHub releases](https://github.com/sremich/netbox-monitor/releases); Docker
images are published to `ghcr.io/sremich/netbox-monitor` per tag.

## v2.4.2 — 2026-07-20

Bugfix: **a placeholder MAC is not a chassis identity.** RouterOS reports
`00:00:00:00:00:00` on loopback interfaces, so two different switches could both
appear to carry the same MAC — the first live crawl merged two distinct MikroTik
switches into one and deleted a real device. All-zeros and all-FF MACs are now
excluded from the identity set and never recorded. If you ran v2.4.0/v2.4.1 with
MikroTik gear, check the logs for `merging duplicate switch` before trusting the
topology.

## v2.4.1 — 2026-07-20

Bugfix for the de-duplication merge: NetBox refuses to reassign an IP while it is
designated as its device's primary — and the duplicate's management IP is exactly
that. The merge now releases the primary designation first, and a failed merge no
longer aborts the rest of the crawl.

## v2.4.0 — 2026-07-20

Feature: **one physical switch, one NetBox device.**

- Every LLDP driver now collects the polled switch's *own* MAC addresses (its
  chassis identity): SNMP `lldpLocChassisId`, MikroTik `/interface print terse`,
  Cisco `show version`, Arista `show lldp local-info`, Aruba `show system`,
  UniFi `ip link` — all best-effort.
- The crawl records those MACs on the device and merges any distinct device
  already carrying one: the duplicate's IPs move to the survivor, the managed
  duplicate is deleted, cables redraw next pass. Human-created devices always
  win a merge and are never deleted; a duplicate holding any unmanaged record
  refuses to merge.
- `_ensure_switch_device` gained the management-IP fallback match, and chassis-MAC
  matching works under the NetBox ≥ 4.2 MAC-object model.
- Journal-entry failures can no longer abort the operation they annotate.

## v2.3.2 — 2026-07-18

Bugfix: **excluded prefixes are no longer polled.** `exclude_prefixes` was
honored only by the ping-discovery scan; the availability monitor still pinged
every managed host each minute regardless. Availability now skips any host whose
IP falls in a configured site's exclude list. DHCP/Proxmox still document a real
reservation or guest IP in an excluded range (intentional).

## v2.3.1 — 2026-07-17

Bugfix: **dashboard sync times render in the viewer's timezone.** Times were
formatted with the server's clock (UTC in Docker) and no label, so a just-run
sync looked an hour stale to a BST viewer. Timestamps now reach the browser as
epochs and render as local time plus a live relative age ("16:39 (just now)"),
with an explicit-UTC fallback when JavaScript is off.

## v2.3.0 — 2026-07-17

Feature release: **config backup/restore, version footer, deploy hardening.**

- **Backup & restore page**: export the whole configuration either encrypted
  (scrypt + AES-256-GCM, passphrase-protected, contains every credential) or
  redacted (secrets replaced by a sentinel; on import the sentinel keeps the
  target's existing values). The `webui` section never leaves the instance.
- **Config schema versioning**: `schema_version` + an append-only migration
  chain; every load path migrates (fixing a latent bug where a v1-shaped
  settings.json silently loaded as zero sites). Golden export fixtures per
  release enforce the compatibility promise in CI.
- **Auto-restore on first boot** from a mounted encrypted export
  (`NBM_RESTORE_FILE` / `NBM_RESTORE_PASSPHRASE[_FILE]` / `NBM_RESTORE_STRICT`).
- Footer with version + GitHub link on every page; `/healthz` endpoint and a
  compose healthcheck; `settings.json` chmod 0600 + `.bak` before import; the
  version is single-sourced from `__init__.py` and CI refuses a mismatched tag;
  a CSRF token guards `/backup/import`.

## v2.2.1 — 2026-07-17

Bugfix: **say why an LLDP switch isn't polled.** Driver/credential failures were
logged at DEBUG, so a failing switch produced no output at all; the dashboard now
names the drivers tried and each error (e.g. `10.0.0.5: cisco/TimeoutError`), and
seeds stranded on an unconfigured site are flagged at startup. README gained
troubleshooting notes for SSH-hostile switches (set an SNMP community) and
seeds left on a retired site.

## v2.2.0 — 2026-07-17

Feature: **Cleanup page & painless site migration.**

- **Cleanup** (top nav): inventories every object the service created — devices,
  VMs, IPs, cables, grouped by site/source/staleness — and bulk-deletes a
  filtered selection with preview and explicit confirm. Human-created objects
  are never touched.
- The sync **auto-migrates** a device to the site that re-discovers it when
  matched by MAC; discovery reports clearly when a site has no scoped prefixes
  to scan.
- Fresh-clone deploy fixed: `docker compose up -d` works with no `.env` or
  `config.yaml`; README gained a no-clone quick start straight from the
  published image.

## v2.1.0 — 2026-07-17

**LLDP fabric crawl.** From a few `lldp-source` seed switches, the LLDP module
now crawls the whole fabric: reads neighbors, follows switch-to-switch links,
auto-creates discovered switches, and documents links as cables. Multi-vendor
drivers (Cisco, Arista, Aruba, MikroTik, UniFi over SSH; SNMP LLDP-MIB
otherwise) with legacy-crypto-tolerant SSH; global credential profiles with a
per-host auth-attempt cap (no credential spraying); a document-only exclusion
list so production routers are drawn into the topology but never logged into.
Also: security hardening (token-leak fixes, CSRF origin checks, restricted test
endpoints, resource-leak fixes).

## v2.0.0 — 2026-07-16

**v2: multi-site + web UI.** FastAPI + Jinja2 + htmx web UI on :8899 (first-run
password, settings, per-site config with live NetBox pickers, status dashboard
with Run-now); multi-site model where each site pairs a NetBox Site with its own
Technitium, Proxmox instances, and discovery scope; runtime `settings.json`
store with hot-reload (no restarts on config change); v1 YAML configs migrate
automatically into a single site.

## Pre-2.0 — 2026-07-16

Initial (untagged) development: the seven sync modules — Technitium DHCP/DNS,
ping discovery with OUI enrichment, availability monitoring with stale tagging,
Proxmox virtualization sync, LLDP topology, TLS certificate tracking — plus the
ownership-tag guard (`managed:netbox-monitor` + `src:*`; never touch human
records), Docker packaging, and CI.
