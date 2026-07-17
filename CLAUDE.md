# netbox-monitor — working notes

Standalone asyncio service that keeps NetBox in sync with reality (Technitium
DNS/DHCP, ping discovery, Proxmox, LLDP topology, TLS certs), plus a FastAPI +
Jinja2 + htmx web UI on :8899. Runs alongside NetBox, talks to everything over APIs.

## Commands

```sh
pip install -e ".[dev]"
ruff check . && ruff format --check .   # line-length 100, rules E,F,I,UP,B
pytest -v                               # asyncio_mode=auto, pythonpath=["src"]
```

Python 3.12, src layout, hatchling. Tests use an in-memory fake of the pynetbox
surface (`tests/conftest.py`), which also provides the shared `store`/`client`/`login`
web-UI fixtures.

---

## THE CONFIG COMPATIBILITY RULE

**Every release must be able to load configs written by previous releases** — both
an on-disk `settings.json` and an exported config file. This is a promise to users
who upgrade in place or restore a backup, and it does not expire.

Any change to `AppConfig`'s **serialized shape** (renaming/removing a field, moving
one between sections, changing a type or its meaning) requires all three of:

1. **Bump `CONFIG_SCHEMA_VERSION`** in `src/netbox_monitor/config.py`.
2. **Add a migration to `MIGRATIONS`**, keyed by the version it migrates **from**.
   Migrations are pure `dict -> dict`, must be idempotent, and are **append-only** —
   deleting one breaks every config still written at that version.
3. **Add a golden fixture** for the outgoing version under
   `tests/fixtures/config_exports/`. `test_a_golden_export_exists_for_the_current_version`
   fails until you do; its docstring has the regeneration command.

**Never edit or delete an existing golden fixture.** `tests/fixtures/` is the
contract, not test data. If a golden stops loading, the migration chain is wrong —
fix the chain. Regenerating the fixture to turn a red test green destroys the
guarantee silently, which is the one failure mode this whole apparatus exists to
prevent.

`config_from_raw()` is the **only** sanctioned path from a serialized dict to an
`AppConfig`; calling `AppConfig.model_validate()` on untrusted/stored input skips
migration. (That bug was real: `bootstrap` did exactly this, so a v1-shaped
settings.json silently loaded as `sites: []` and every module no-opped.)

Only add a `settings_json/` fixture when a release actually changes the on-disk
shape. A pre-2.3.0 *export* fixture cannot exist — the format ships in 2.3.0 — so
earlier compatibility is proven by the `settings_json/` family instead.

## Secrets

- **Any new secret-bearing config field must be added to `SECRET_PATHS`**
  (`config_transfer.py`). `test_secret_paths_covers_every_secret_field_in_the_model`
  reflectively walks the models and fails until every credential-looking field is
  either declared there or listed in `_KNOWN_NON_SECRETS` with a reason. Without it,
  a new field silently ships in cleartext inside redacted exports.
- **`webui` is never exported.** `password_hash` + `session_secret` are dropped on
  export and overwritten from the target on import. An imported `webui` would be an
  instant admin handover plus forgeable sessions. Guarded on both sides, tested
  independently — don't "simplify" either half away.
- `settings.json` holds plaintext tokens: mode 0600, and chmod the temp file
  **before** `os.replace`, never the target after.
- Never commit real tokens, logs, or `data/`. Runtime logs have leaked a token
  before (httpx logs full URLs at INFO, including `?token=`).

## House conventions

- **The version lives only in `src/netbox_monitor/__init__.py`.** pyproject reads it
  via hatchling; CI fails a `v*` tag that disagrees with it.
- Web UI: routes are closures inside `create_app` (no routers/`Depends`). Page routes
  use `guard()`; htmx/API routes use `authed()` and return 401. Hand-built HTML
  fragments must `html.escape()` **every** interpolated value.
- Secret inputs render as empty `type="password"` with a `•••` placeholder; **a blank
  field means keep the stored value**. Redacted imports follow the same rule.
- Constants for templates go in `templates.env.globals`; per-request values (e.g.
  `csrf`) go through `render()`.
- Ownership guard: everything the service creates is tagged `managed:netbox-monitor`
  + a `src:*` tag, and it never deletes or lifecycle-edits records lacking them.
  Hand-curated NetBox data is not ours to touch.

## Known follow-ups

- CSRF tokens are enforced on `/backup/import` only. The origin/referer middleware
  fails open when neither header is present, so the remaining POST routes
  (`/settings`, `/sites/*`, `/cleanup/delete`, `/run/*`) should get the token too —
  it was scoped to one route to avoid breaking every existing test in one release.
- `_site_from_form` / `_lldp_credentials_from_form` still know secret field paths
  ad hoc; they could be rewired onto `SECRET_PATHS`.
