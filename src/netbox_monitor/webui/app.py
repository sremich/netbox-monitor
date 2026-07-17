"""Web UI: configuration (global settings, sites, tokens), status dashboard,
run-now triggers, and connection tests. Server-rendered Jinja2 + htmx."""

from __future__ import annotations

import asyncio
import html
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from starlette.datastructures import UploadFile as StarletteUploadFile

from netbox_monitor import __version__, config_transfer
from netbox_monitor.clients.netbox import NetBoxClient, slugify
from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    ConfigSchemaTooNewError,
    LifecycleConfig,
    LldpCredential,
    ProxmoxInstance,
    SiteConfig,
    SiteDiscoveryConfig,
    SiteLldpConfig,
    TechnitiumConfig,
)
from netbox_monitor.scheduler import Engine
from netbox_monitor.settings_store import SettingsStore
from netbox_monitor.status import StatusRegistry
from netbox_monitor.sync import cleanup
from netbox_monitor.webui.auth import (
    SESSION_COOKIE,
    check_csrf_token,
    check_session_token,
    hash_password,
    make_csrf_token,
    make_session_token,
    verify_password,
)

log = structlog.get_logger(__name__)

BASE_DIR = Path(__file__).parent

# hardcoded rather than read from [project.urls]: pytest runs with pythonpath=src,
# where the package imports but has no dist metadata to read.
REPO_URL = "https://github.com/sremich/netbox-monitor"

# a config export is a few KB; anything near this is not one. Starlette spools a
# large upload to disk, but .read() would still pull it all into memory.
MAX_IMPORT_BYTES = 1 << 20

MODULES = ["dhcp", "dns", "discovery", "availability", "proxmox", "lldp", "certs"]
MODULE_LABELS = {
    "dhcp": "DHCP leases",
    "dns": "DNS records",
    "discovery": "Ping discovery",
    "availability": "Availability monitor",
    "proxmox": "Proxmox sync",
    "lldp": "LLDP topology",
    "certs": "TLS certificates",
}


def format_timestamp(value: float | None) -> Any:
    """Render a stored epoch as a ``<time>`` element the browser localizes.

    The server runs in its own timezone (UTC in Docker), so formatting here would
    show every viewer the server's clock — a UK user in summer reads a just-now sync
    as an hour old. Instead we emit the epoch as ``data-ts`` plus a UTC fallback;
    a small script (base.html) rewrites it to the viewer's local time and a relative
    age. Without JS the fallback is still correct and explicitly labelled UTC.
    """
    if not value:
        return "never"
    dt = datetime.fromtimestamp(value, tz=UTC)
    fallback = dt.strftime("%H:%M:%S UTC")
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return Markup(f'<time data-ts="{int(value)}" datetime="{iso}">{fallback}</time>')


def create_app(store: SettingsStore, engine: Engine | None, status: StatusRegistry) -> FastAPI:
    app = FastAPI(title="netbox-monitor", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=BASE_DIR / "templates")
    started = time.monotonic()

    templates.env.filters["timestamp"] = format_timestamp
    # globals, not render() context: these are constants, and a template rendered
    # outside render() would otherwise lose its footer silently
    templates.env.globals["version"] = __version__
    templates.env.globals["repo_url"] = REPO_URL

    # --------------------------------------------------------------- health

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Liveness for container healthchecks — deliberately unauthenticated, since
        Docker's HEALTHCHECK carries no session cookie.

        Reports only non-identifying facts: no URLs, no site names, no config. The
        status never depends on NetBox being reachable and the code is always 200 —
        a NetBox outage that made Docker kill the monitor would just amplify it.
        Degradation belongs in a field, not the status code.
        """
        cfg = store.get()
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "config_schema": CONFIG_SCHEMA_VERSION,
                "configured": bool(cfg.netbox.configured),
                "sites": len(cfg.sites),
                "engine": "running" if engine is not None else "disabled",
                "uptime_s": round(time.monotonic() - started, 1),
            }
        )

    @app.middleware("http")
    async def csrf_origin_guard(request: Request, call_next):
        # CSRF defense-in-depth (on top of the SameSite cookie): reject any
        # state-changing request whose Origin/Referer host isn't our own.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            source = request.headers.get("origin") or request.headers.get("referer")
            if source:
                src_host = urlparse(source).netloc
                if src_host and src_host != request.headers.get("host"):
                    return HTMLResponse("cross-origin request blocked", status_code=403)
        return await call_next(request)

    # ------------------------------------------------------------------ auth

    def authed(request: Request) -> bool:
        cfg = store.get().webui
        return check_session_token(cfg.session_secret, request.cookies.get(SESSION_COOKIE))

    def guard(request: Request) -> RedirectResponse | None:
        cfg = store.get().webui
        if not cfg.password_hash:
            return RedirectResponse("/setup", status_code=303)
        if not authed(request):
            return RedirectResponse("/login", status_code=303)
        return None

    def render(request: Request, template: str, **ctx: Any) -> HTMLResponse:
        # csrf goes here rather than in env.globals: it is per-request and needs the
        # store, unlike the constant version/repo_url globals above
        return templates.TemplateResponse(
            request,
            template,
            {
                "modules": MODULES,
                "module_labels": MODULE_LABELS,
                "csrf": make_csrf_token(store.get().webui.session_secret),
                **ctx,
            },
        )

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request):
        if store.get().webui.password_hash:
            return RedirectResponse("/login", status_code=303)
        return render(request, "setup.html")

    @app.post("/setup")
    async def setup_submit(request: Request):
        if store.get().webui.password_hash:
            return RedirectResponse("/login", status_code=303)
        form = await request.form()
        password = str(form.get("password") or "")
        if len(password) < 8 or password != str(form.get("confirm") or ""):
            return render(
                request, "setup.html", error="Passwords must match and be at least 8 characters"
            )
        store.update_field(lambda c: setattr(c.webui, "password_hash", hash_password(password)))
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            make_session_token(store.get().webui.session_secret),
            httponly=True,
            samesite="strict",
        )
        return response

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if not store.get().webui.password_hash:
            return RedirectResponse("/setup", status_code=303)
        return render(request, "login.html")

    @app.post("/login")
    async def login_submit(request: Request):
        form = await request.form()
        cfg = store.get().webui
        if not verify_password(str(form.get("password") or ""), cfg.password_hash):
            return render(request, "login.html", error="Wrong password")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            make_session_token(cfg.session_secret),
            httponly=True,
            samesite="strict",
        )
        return response

    @app.get("/logout")
    async def logout():
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    # ------------------------------------------------------------- dashboard

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if redirect := guard(request):
            return redirect
        config = store.get()
        snapshot = await status.snapshot()
        return render(
            request,
            "dashboard.html",
            config=config,
            snapshot=snapshot,
            engine_running=engine is not None and bool(engine.triggers),
        )

    @app.post("/run/{module}", response_class=HTMLResponse)
    async def run_now(request: Request, module: str):
        if redirect := guard(request):
            return redirect
        if module not in MODULES:
            return HTMLResponse('<span class="flash">unknown module</span>', status_code=400)
        ok = engine.run_now(module) if engine else False
        message = f"{module} triggered" if ok else f"{module} is not currently scheduled"
        return HTMLResponse(f'<span class="flash">{html.escape(message)}</span>')

    # -------------------------------------------------------------- settings

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if redirect := guard(request):
            return redirect
        return render(request, "settings.html", config=store.get(), saved=False)

    @app.post("/settings", response_class=HTMLResponse)
    async def settings_submit(request: Request):
        if redirect := guard(request):
            return redirect
        form = await request.form()

        # password change is validated up front (needs the current password + length)
        new_password = str(form.get("new_password") or "")
        if new_password:
            if not verify_password(
                str(form.get("current_password") or ""), store.get().webui.password_hash
            ):
                return render(
                    request,
                    "settings.html",
                    config=store.get(),
                    saved=False,
                    error="Current password is incorrect — password not changed.",
                )
            if len(new_password) < 8:
                return render(
                    request,
                    "settings.html",
                    config=store.get(),
                    saved=False,
                    error="New password must be at least 8 characters.",
                )

        def apply(c):
            c.netbox.url = str(form.get("netbox_url") or "").strip().rstrip("/")
            token = str(form.get("netbox_token") or "").strip()
            if token:
                c.netbox.token = token
            c.netbox.verify_ssl = form.get("netbox_verify_ssl") == "on"
            c.dry_run = form.get("dry_run") == "on"
            c.log_level = str(form.get("log_level") or "INFO")
            c.lifecycle = LifecycleConfig(
                delete_dhcp_on_expiry=form.get("delete_dhcp_on_expiry") == "on",
                stale_grace_delete_days=int(form.get("stale_grace_delete_days"))
                if str(form.get("stale_grace_delete_days") or "").strip()
                else None,
            )
            c.availability.stale_after = int(form.get("stale_after") or 600)
            for module in MODULES:
                section = getattr(c, "proxmox_sync" if module == "proxmox" else module)
                section.interval = max(15, int(form.get(f"interval_{module}") or section.interval))
                section.enabled = form.get(f"enabled_{module}") == "on"
            # LLDP crawl settings
            c.lldp.crawl_enabled = form.get("lldp_crawl_enabled") == "on"
            c.lldp.max_switches = max(1, int(form.get("lldp_max_switches") or 100))
            c.lldp.max_depth = max(1, int(form.get("lldp_max_depth") or 8))
            c.lldp.credentials = _lldp_credentials_from_form(form, c.lldp.credentials)
            c.lldp.exclude_hosts = _split_hosts(str(form.get("lldp_exclude_hosts") or ""))
            if new_password:
                c.webui.password_hash = hash_password(new_password)
                # rotate the session secret so existing cookies are invalidated
                c.webui.session_secret = secrets.token_hex(32)

        try:
            store.update_field(apply)
        except Exception as exc:
            return render(request, "settings.html", config=store.get(), saved=False, error=str(exc))
        return render(request, "settings.html", config=store.get(), saved=True)

    # ----------------------------------------------------------------- sites

    @app.get("/sites", response_class=HTMLResponse)
    async def sites_page(request: Request):
        if redirect := guard(request):
            return redirect
        return render(request, "sites.html", config=store.get())

    @app.get("/sites/new", response_class=HTMLResponse)
    async def site_new(request: Request):
        if redirect := guard(request):
            return redirect
        site = SiteConfig(id="", name="")
        return render(request, "site_edit.html", site=site, is_new=True, config=store.get())

    @app.get("/sites/{site_id}", response_class=HTMLResponse)
    async def site_edit(request: Request, site_id: str):
        if redirect := guard(request):
            return redirect
        site = next((s for s in store.get().sites if s.id == site_id), None)
        if site is None:
            return RedirectResponse("/sites", status_code=303)
        return render(request, "site_edit.html", site=site, is_new=False, config=store.get())

    @app.post("/sites/{site_id}/delete")
    async def site_delete(request: Request, site_id: str):
        if redirect := guard(request):
            return redirect
        store.update_field(lambda c: setattr(c, "sites", [s for s in c.sites if s.id != site_id]))
        return RedirectResponse("/sites", status_code=303)

    @app.post("/sites/new")
    @app.post("/sites/{site_id}")
    async def site_save(request: Request, site_id: str | None = None):
        if redirect := guard(request):
            return redirect
        form = await request.form()
        existing = (
            next((s for s in store.get().sites if s.id == site_id), None) if site_id else None
        )
        try:
            site = _site_from_form(form, existing)
        except ValueError as exc:
            template_site = existing or SiteConfig(id="", name=str(form.get("name") or ""))
            return render(
                request,
                "site_edit.html",
                site=template_site,
                is_new=existing is None,
                config=store.get(),
                error=str(exc),
            )

        def apply(c):
            others = [s for s in c.sites if s.id != site.id and s.id != site_id]
            if any(s.id == site.id for s in others):
                raise ValueError(f"site id '{site.id}' already exists")
            c.sites = [*others, site]

        store.update_field(apply)
        return RedirectResponse("/sites", status_code=303)

    # --------------------------------------------------------------- cleanup

    def _cleanup_filters(form: Any) -> dict:
        types = form.getlist("object_types") or list(cleanup.OBJECT_TYPES)
        nsd = str(form.get("not_seen_days") or "").strip()
        return {
            "object_types": tuple(t for t in types if t in cleanup.OBJECT_TYPES),
            "site_slug": (str(form.get("site_slug") or "").strip() or None),
            "source": (str(form.get("source") or "").strip() or None),
            "only_stale": form.get("only_stale") == "on",
            "not_seen_days": int(nsd) if nsd else None,
        }

    @app.get("/cleanup", response_class=HTMLResponse)
    async def cleanup_page(request: Request):
        if redirect := guard(request):
            return redirect
        cfg = store.get()
        rows: list = []
        error = None
        if cfg.netbox.configured:
            nb = NetBoxClient(cfg.netbox, dry_run=True)
            try:
                rows = await asyncio.to_thread(cleanup.inventory, nb)
            except Exception as exc:
                error = str(exc)
        sites = sorted({r.site for r in rows if r.site not in ("—", "unassigned")})
        sources = sorted({r.source for r in rows if r.source != "?"})
        return render(
            request,
            "cleanup.html",
            rows=rows,
            sites=sites,
            sources=sources,
            object_types=cleanup.OBJECT_TYPES,
            error=error,
            dry_run=cfg.dry_run,
        )

    @app.post("/cleanup/preview", response_class=HTMLResponse)
    async def cleanup_preview(request: Request):
        if not authed(request):
            return HTMLResponse("not authenticated", status_code=401)
        cfg = store.get()
        if not cfg.netbox.configured:
            return HTMLResponse('<span class="error">NetBox not configured</span>')
        filters = _cleanup_filters(await request.form())
        nb = NetBoxClient(cfg.netbox, dry_run=True)
        result = await asyncio.to_thread(
            lambda: cleanup.delete_managed(nb, dry_run=True, **filters)
        )
        detail = ", ".join(f"{n} {t}" for t, n in result.counts.items()) or "nothing"
        return HTMLResponse(
            f'<span class="flash"><strong>{result.total}</strong> objects would be '
            f"deleted ({html.escape(detail)}).</span>"
        )

    @app.post("/cleanup/delete", response_class=HTMLResponse)
    async def cleanup_delete(request: Request):
        if not authed(request):
            return HTMLResponse("not authenticated", status_code=401)
        form = await request.form()
        if form.get("confirm") != "on":
            return HTMLResponse('<span class="error">confirmation not checked</span>')
        cfg = store.get()
        if not cfg.netbox.configured:
            return HTMLResponse('<span class="error">NetBox not configured</span>')
        filters = _cleanup_filters(form)
        nb = NetBoxClient(cfg.netbox, dry_run=cfg.dry_run)
        result = await asyncio.to_thread(lambda: cleanup.delete_managed(nb, **filters))
        detail = ", ".join(f"{n} {t}" for t, n in result.counts.items()) or "nothing"
        verb = "would delete" if result.dry_run else "deleted"
        rerun = ""
        if not result.dry_run and form.get("rerun_discovery") == "on" and engine:
            engine.run_now("discovery")
            rerun = " — discovery re-run triggered"
        return HTMLResponse(
            f'<span class="okbox">{verb} <strong>{result.total}</strong> objects '
            f"({html.escape(detail)}){rerun}.</span>"
        )

    # --------------------------------------------------------- backup/restore

    @app.get("/backup", response_class=HTMLResponse)
    async def backup_page(request: Request):
        if redirect := guard(request):
            return redirect
        return render(request, "backup.html", min_passphrase=config_transfer.MIN_PASSPHRASE)

    @app.post("/backup/export")
    async def backup_export(request: Request):
        if redirect := guard(request):
            return redirect
        form = await request.form()
        encrypted = form.get("mode") != "redacted"
        passphrase = str(form.get("passphrase") or "")

        if encrypted:
            if passphrase != str(form.get("passphrase_confirm") or ""):
                return render(request, "backup.html", error="Passphrases do not match.")
            if len(passphrase) < config_transfer.MIN_PASSPHRASE:
                least = config_transfer.MIN_PASSPHRASE
                return render(
                    request,
                    "backup.html",
                    error=f"Passphrase must be at least {least} characters.",
                )
        try:
            blob = config_transfer.export_config(
                store.get(), passphrase=passphrase if encrypted else None
            )
        except config_transfer.ConfigTransferError as exc:
            return render(request, "backup.html", error=str(exc))

        filename = config_transfer.export_filename(__version__, encrypted)
        return Response(
            content=blob,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                # an encrypted export is every token the user owns — never cache it
                "Cache-Control": "no-store",
            },
        )

    @app.post("/backup/import", response_class=HTMLResponse)
    async def backup_import(request: Request):
        if not authed(request):
            return HTMLResponse("not authenticated", status_code=401)
        form = await request.form()
        if not check_csrf_token(store.get().webui.session_secret, str(form.get("csrf") or "")):
            return HTMLResponse('<span class="error">invalid CSRF token — reload the page</span>')
        if form.get("confirm") != "on":
            return HTMLResponse('<span class="error">confirmation not checked</span>')

        upload = form.get("file")
        if not isinstance(upload, StarletteUploadFile) or not upload.filename:
            return HTMLResponse('<span class="error">no file chosen</span>')

        declared = request.headers.get("content-length")
        if declared and int(declared) > MAX_IMPORT_BYTES:
            return HTMLResponse('<span class="error">file too large</span>')
        blob = await upload.read()
        if len(blob) > MAX_IMPORT_BYTES:  # the header is advisory; the read is not
            return HTMLResponse('<span class="error">file too large</span>')

        try:
            result = config_transfer.import_config(
                blob, passphrase=str(form.get("passphrase") or "") or None, current=store.get()
            )
        except (config_transfer.ConfigTransferError, ConfigSchemaTooNewError) as exc:
            return HTMLResponse(f'<span class="error">{html.escape(str(exc)[:200])}</span>')
        except Exception as exc:  # malformed payload that still parsed as JSON
            log.warning("config import failed", error=str(exc))
            return HTMLResponse(
                f'<span class="error">could not import: {html.escape(str(exc)[:200])}</span>'
            )

        # replace() bumps the generation; the scheduler reloads within ~2s
        store.replace(result.config, backup=True)
        log.info(
            "config imported",
            source_app_version=result.source_app_version,
            encrypted=result.encrypted,
            unresolved=list(result.unresolved_secrets),
        )

        note = f"Imported from v{html.escape(result.source_app_version)}"
        if result.migrated_from is not None:
            note += f" (migrated from config schema {result.migrated_from})"
        warning = ""
        if result.unresolved_secrets:
            paths = ", ".join(html.escape(p) for p in result.unresolved_secrets)
            warning = (
                f'<br><small class="error">{len(result.unresolved_secrets)} secret(s) could not '
                f"be restored and are now blank: {paths}. Set them on the Settings/Sites "
                "pages.</small>"
            )
        return HTMLResponse(
            f'<span class="okbox">{note}. The previous config was saved to '
            f"settings.json.bak.{warning}</span>"
        )

    # ------------------------------------------------------- NetBox pickers

    def _netbox_api(url: str | None = None, token: str | None = None, verify: bool | None = None):
        import pynetbox

        cfg = store.get().netbox
        api = pynetbox.api(url or cfg.url, token=token or cfg.token)
        api.http_session.verify = cfg.verify_ssl if verify is None else verify
        return api

    @app.get("/api/netbox/sites")
    async def netbox_sites(request: Request):
        if not authed(request):
            return JSONResponse([], status_code=401)

        def fetch():
            api = _netbox_api()
            return [{"slug": s.slug, "name": s.name} for s in api.dcim.sites.all()]

        try:
            return JSONResponse(await asyncio.to_thread(fetch))
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

    @app.get("/api/netbox/prefixes")
    async def netbox_prefixes(request: Request):
        if not authed(request):
            return JSONResponse([], status_code=401)

        def fetch():
            api = _netbox_api()
            return [str(p.prefix) for p in api.ipam.prefixes.filter(status="active")]

        try:
            return JSONResponse(await asyncio.to_thread(fetch))
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

    # ------------------------------------------------------ connection tests

    def _test_fragment(ok: bool, detail: str) -> HTMLResponse:
        icon = "✅" if ok else "❌"
        return HTMLResponse(f'<span class="test-result">{icon} {html.escape(detail)}</span>')

    @app.post("/test/netbox", response_class=HTMLResponse)
    async def test_netbox(request: Request):
        if not authed(request):
            return _test_fragment(False, "not authenticated")
        form = await request.form()
        url = str(form.get("netbox_url") or "").strip().rstrip("/")
        token = str(form.get("netbox_token") or "").strip()
        if not token:
            if _same_origin(url, store.get().netbox.url):
                # only forward the saved token to the URL it belongs to (anti-SSRF/exfil)
                token = store.get().netbox.token
            else:
                return _test_fragment(False, "enter a token to test a different NetBox URL")
        verify = form.get("netbox_verify_ssl") == "on"

        def check():
            import pynetbox

            # build directly with the resolved token — never fall back to the saved
            # token for a foreign URL (that fallback lives only in _netbox_api, used
            # by the same-origin pickers)
            api = pynetbox.api(url, token=token)
            api.http_session.verify = verify
            return str(api.status().get("netbox-version"))

        try:
            version = await asyncio.to_thread(check)
            return _test_fragment(True, f"NetBox {version}")
        except Exception as exc:
            return _test_fragment(False, str(exc)[:200])

    def _saved_site(form: Any) -> SiteConfig | None:
        site_id = str(form.get("site_id") or "")
        return next((s for s in store.get().sites if s.id == site_id), None)

    @app.post("/test/technitium", response_class=HTMLResponse)
    async def test_technitium(request: Request):
        if not authed(request):
            return _test_fragment(False, "not authenticated")
        form = await request.form()
        from netbox_monitor.clients.technitium import TechnitiumClient

        url = str(form.get("tech_url") or "").strip().rstrip("/")
        token = str(form.get("tech_token") or "").strip()
        if not token:  # blank field = use the saved token, only for its own URL
            saved = _saved_site(form)
            if saved and saved.technitium and _same_origin(url, saved.technitium.url):
                token = saved.technitium.token
        client = TechnitiumClient(TechnitiumConfig(url=url, token=token))
        try:
            zones = await client.list_zones()
            return _test_fragment(True, f"{len(zones)} zones visible")
        except Exception as exc:
            return _test_fragment(False, str(exc)[:200])
        finally:
            await client.close()

    @app.post("/test/proxmox", response_class=HTMLResponse)
    async def test_proxmox(request: Request):
        if not authed(request):
            return _test_fragment(False, "not authenticated")
        form = await request.form()
        # the enclosing form posts every row (including the blank template row):
        # test the first row with a host filled in
        hosts = [str(h).strip() for h in form.getlist("px_host")]
        index = next((i for i, h in enumerate(hosts) if h), None)
        if index is None:
            return _test_fragment(False, "no Proxmox host filled in")

        def row(field: str, default: str = "") -> str:
            values = form.getlist(field)
            return str(values[index]).strip() if index < len(values) else default

        host = hosts[index]
        token_value = row("px_token_value")
        if not token_value:  # blank field = use the saved token for this host
            saved = _saved_site(form)
            if saved:
                for prev in saved.proxmox:
                    if prev.host == host:
                        token_value = prev.token_value
        instance = ProxmoxInstance(
            host=host,
            port=int(row("px_port") or 8006),
            user=row("px_user") or "root@pam",
            token_name=row("px_token_name"),
            token_value=token_value,
            verify_ssl=False,
        )

        def check():
            from netbox_monitor.clients.proxmox import ProxmoxClient

            client = ProxmoxClient(instance)
            nodes = client.nodes()
            return f"cluster '{client.cluster_name()}', nodes: " + ", ".join(
                n["node"] for n in nodes
            )

        try:
            detail = await asyncio.to_thread(check)
            return _test_fragment(True, detail)
        except Exception as exc:
            return _test_fragment(False, str(exc)[:200])

    return app


# ------------------------------------------------------------- form parsing


def _same_origin(a: str, b: str) -> bool:
    """True if two URLs share scheme+host+port. Used to ensure a saved credential
    is only ever forwarded to the URL it belongs to (anti-SSRF / anti-exfiltration)."""
    if not a or not b:
        return False
    pa, pb = urlparse(a if "://" in a else f"//{a}"), urlparse(b if "://" in b else f"//{b}")
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _csv_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _split_hosts(value: str) -> list[str]:
    return [h for h in re.split(r"[,\s]+", value) if h.strip()]


def _lldp_credentials_from_form(form: Any, previous: list[LldpCredential]) -> list[LldpCredential]:
    """Parse the repeating LLDP credential-profile rows. Blank password/community
    fields keep the value from the same-named existing profile."""
    prev_by_name = {p.name: p for p in previous}
    names = form.getlist("cred_name")
    drivers = form.getlist("cred_driver")
    users = form.getlist("cred_username")
    passwords = form.getlist("cred_password")
    communities = form.getlist("cred_community")
    creds: list[LldpCredential] = []
    for i, name in enumerate(names):
        name = str(name).strip()
        if not name:
            continue
        prev = prev_by_name.get(name)

        def pick(values, idx=i, keep=""):
            return str(values[idx]).strip() if idx < len(values) else keep

        password = pick(passwords) or (prev.password if prev else "")
        community = pick(communities) or (prev.snmp_community if prev else "")
        creds.append(
            LldpCredential(
                name=name,
                driver=pick(drivers, keep="auto") or "auto",
                username=pick(users),
                password=password,
                snmp_community=community,
            )
        )
    return creds


def _site_from_form(form: Any, existing: SiteConfig | None) -> SiteConfig:
    name = str(form.get("name") or "").strip()
    if not name:
        raise ValueError("site name is required")
    site_id = existing.id if existing else slugify(name)

    netbox_site = str(form.get("netbox_site") or "").strip()
    netbox_site_name = str(form.get("netbox_site_name") or "").strip()
    if netbox_site == "__new__":
        if not netbox_site_name:
            raise ValueError("provide a name for the new NetBox site")
        netbox_site = slugify(netbox_site_name)
    elif not netbox_site:
        raise ValueError("select a NetBox site")

    technitium = None
    tech_url = str(form.get("tech_url") or "").strip().rstrip("/")
    tech_token = str(form.get("tech_token") or "").strip()
    if not tech_token and existing and existing.technitium:
        tech_token = existing.technitium.token  # blank token field = keep current
    if tech_url:
        technitium = TechnitiumConfig(url=tech_url, token=tech_token)

    proxmox: list[ProxmoxInstance] = []
    hosts = form.getlist("px_host")
    ports = form.getlist("px_port")
    users = form.getlist("px_user")
    token_names = form.getlist("px_token_name")
    token_values = form.getlist("px_token_value")
    for i, host in enumerate(hosts):
        host = str(host).strip()
        if not host:
            continue
        token_value = str(token_values[i] if i < len(token_values) else "").strip()
        if not token_value and existing:
            for prev in existing.proxmox:
                if prev.host == host:
                    token_value = prev.token_value
        proxmox.append(
            ProxmoxInstance(
                host=host,
                port=int(ports[i]) if i < len(ports) and str(ports[i]).strip() else 8006,
                user=str(users[i] if i < len(users) else "").strip() or "root@pam",
                token_name=str(token_names[i] if i < len(token_names) else "").strip(),
                token_value=token_value,
                verify_ssl=False,
            )
        )

    include = form.getlist("include_prefixes") + _csv_list(str(form.get("include_extra") or ""))
    exclude = form.getlist("exclude_prefixes") + _csv_list(str(form.get("exclude_extra") or ""))

    # LLDP: blank secret fields keep the stored values
    prev_lldp = existing.lldp if existing else SiteLldpConfig()
    lldp = SiteLldpConfig(
        enabled=form.get("lldp_enabled") == "on",
        snmp_community=str(form.get("lldp_snmp_community") or "").strip()
        or prev_lldp.snmp_community,
        ssh_username=str(form.get("lldp_ssh_username") or "").strip(),
        ssh_password=str(form.get("lldp_ssh_password") or "").strip() or prev_lldp.ssh_password,
    )

    return SiteConfig(
        id=site_id,
        name=name,
        netbox_site=netbox_site,
        netbox_site_name=netbox_site_name or name,
        technitium=technitium,
        proxmox=proxmox,
        discovery=SiteDiscoveryConfig(
            enabled=form.get("discovery_enabled") == "on",
            include_prefixes=sorted(set(map(str, include))),
            exclude_prefixes=sorted(set(map(str, exclude))),
        ),
        lldp=lldp,
        dhcp_enabled=form.get("dhcp_enabled") == "on",
        dns_enabled=form.get("dns_enabled") == "on",
        proxmox_enabled=form.get("proxmox_enabled") == "on",
    )
