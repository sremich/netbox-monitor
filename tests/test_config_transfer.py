"""Config export/import: crypto envelope, redaction, and the secret inventory.

The rules being defended here:
  - an encrypted export round-trips every credential, and leaks none in the clear
  - a redacted export leaks nothing, and importing it keeps the target's secrets
  - `webui` never leaves the instance, in either direction
  - a config from a newer build is refused rather than mangled
"""

import json
import re

import pytest

from netbox_monitor.config import (
    CONFIG_SCHEMA_VERSION,
    AppConfig,
    ConfigSchemaTooNewError,
    LldpConfig,
    LldpCredential,
    NetBoxConfig,
    ProxmoxInstance,
    SiteConfig,
    SiteLldpConfig,
    TechnitiumConfig,
    WebUIConfig,
)
from netbox_monitor.config_transfer import (
    REDACTED,
    SECRET_PATHS,
    BadPassphrase,
    ConfigTransferError,
    UnsupportedFormat,
    export_config,
    export_filename,
    import_config,
    peek,
)

PASSPHRASE = "correct-horse-battery-staple"

# one unique marker per secret field, so a leak names the field that leaked
MARKERS = {
    "netbox_token": "MARKER-netbox-token",
    "tech_token": "MARKER-technitium-token",
    "px_token": "MARKER-proxmox-token-value",
    "site_snmp": "MARKER-site-snmp-community",
    "site_ssh": "MARKER-site-ssh-password",
    "cred_pw": "MARKER-cred-password",
    "cred_snmp": "MARKER-cred-snmp-community",
}


def full_config() -> AppConfig:
    """A config with every secret-bearing field populated by a unique marker."""
    return AppConfig(
        netbox=NetBoxConfig(url="http://nb", token=MARKERS["netbox_token"]),
        sites=[
            SiteConfig(
                id="home",
                name="Home",
                netbox_site="home",
                technitium=TechnitiumConfig(url="http://dns", token=MARKERS["tech_token"]),
                proxmox=[
                    ProxmoxInstance(
                        host="10.0.0.91",
                        user="monitor@pve",
                        token_name="nbm",
                        token_value=MARKERS["px_token"],
                    )
                ],
                lldp=SiteLldpConfig(
                    enabled=True,
                    snmp_community=MARKERS["site_snmp"],
                    ssh_username="admin",
                    ssh_password=MARKERS["site_ssh"],
                ),
            )
        ],
        lldp=LldpConfig(
            credentials=[
                LldpCredential(
                    name="p1",
                    driver="mikrotik",
                    username="admin",
                    password=MARKERS["cred_pw"],
                    snmp_community=MARKERS["cred_snmp"],
                )
            ]
        ),
        webui=WebUIConfig(password_hash="pbkdf2$1$aa$bb", session_secret="SESSIONSECRET"),
    )


# ------------------------------------------------------------ encrypted mode


def test_encrypted_round_trip_preserves_every_secret():
    blob = export_config(full_config(), passphrase=PASSPHRASE)
    result = import_config(blob, passphrase=PASSPHRASE, current=AppConfig())

    config = result.config
    assert result.encrypted is True
    assert config.netbox.token == MARKERS["netbox_token"]
    assert config.sites[0].technitium.token == MARKERS["tech_token"]
    assert config.sites[0].proxmox[0].token_value == MARKERS["px_token"]
    assert config.sites[0].lldp.snmp_community == MARKERS["site_snmp"]
    assert config.sites[0].lldp.ssh_password == MARKERS["site_ssh"]
    assert config.lldp.credentials[0].password == MARKERS["cred_pw"]
    assert config.lldp.credentials[0].snmp_community == MARKERS["cred_snmp"]
    assert result.unresolved_secrets == ()


def test_encrypted_blob_leaks_no_secret_in_the_clear():
    blob = export_config(full_config(), passphrase=PASSPHRASE)
    for field, marker in MARKERS.items():
        assert marker.encode() not in blob, f"{field} leaked into the ciphertext envelope"


def test_wrong_passphrase_is_refused():
    blob = export_config(full_config(), passphrase=PASSPHRASE)
    with pytest.raises(BadPassphrase):
        import_config(blob, passphrase="not-the-passphrase", current=AppConfig())


def test_encrypted_export_without_passphrase_is_refused():
    blob = export_config(full_config(), passphrase=PASSPHRASE)
    with pytest.raises(ConfigTransferError, match="passphrase is required"):
        import_config(blob, passphrase=None, current=AppConfig())


def test_tampered_header_is_detected():
    """The header is AEAD associated data — editing it must break authentication.

    Without that binding an attacker could rewrite config_schema/app_version (or
    weaken the KDF parameters) on an otherwise valid envelope. This is the property
    Fernet could not give us.
    """
    envelope = json.loads(export_config(full_config(), passphrase=PASSPHRASE))
    envelope["app_version"] = "9.9.9"
    with pytest.raises(BadPassphrase):
        import_config(json.dumps(envelope).encode(), passphrase=PASSPHRASE, current=AppConfig())


def test_tampered_kdf_parameters_are_detected():
    envelope = json.loads(export_config(full_config(), passphrase=PASSPHRASE))
    envelope["kdf"]["n"] = 1024  # weaken the work factor
    with pytest.raises(BadPassphrase):
        import_config(json.dumps(envelope).encode(), passphrase=PASSPHRASE, current=AppConfig())


def test_absurd_kdf_parameters_are_refused_before_deriving():
    """An envelope claiming n=2**30 would be a one-request OOM if honoured."""
    envelope = json.loads(export_config(full_config(), passphrase=PASSPHRASE))
    envelope["kdf"]["n"] = 1 << 30
    with pytest.raises(UnsupportedFormat, match="out of range"):
        import_config(json.dumps(envelope).encode(), passphrase=PASSPHRASE, current=AppConfig())


def test_short_passphrase_refused_on_export():
    with pytest.raises(ConfigTransferError, match="at least"):
        export_config(full_config(), passphrase="short")


def test_empty_passphrase_is_an_error_not_a_silent_redaction():
    """Coercing "" to redacted would hand back a file the caller thinks holds
    their tokens."""
    with pytest.raises(ConfigTransferError):
        export_config(full_config(), passphrase="")


# ------------------------------------------------------------- redacted mode


def test_redacted_export_leaks_no_secret():
    blob = export_config(full_config(), passphrase=None)
    for field, marker in MARKERS.items():
        assert marker.encode() not in blob, f"{field} leaked into the redacted export"
    assert REDACTED.encode() in blob


def test_redacted_import_keeps_the_targets_existing_secrets():
    blob = export_config(full_config(), passphrase=None)
    result = import_config(blob, passphrase=None, current=full_config())

    config = result.config
    assert config.netbox.token == MARKERS["netbox_token"]
    assert config.sites[0].proxmox[0].token_value == MARKERS["px_token"]
    assert config.lldp.credentials[0].password == MARKERS["cred_pw"]
    assert result.unresolved_secrets == ()


def test_redacted_import_reports_secrets_it_cannot_resolve():
    blob = export_config(full_config(), passphrase=None)
    result = import_config(blob, passphrase=None, current=AppConfig())  # nothing to merge from

    assert result.config.netbox.token == ""  # blanked, never guessed
    assert "netbox.token" in result.unresolved_secrets
    assert len(result.unresolved_secrets) == len(MARKERS)


def test_redacted_import_matches_by_identity_not_position():
    """A reordered export must not attach one host's token to another host."""
    current = full_config()
    current.sites[0].proxmox = [
        ProxmoxInstance(host="10.0.0.91", user="u", token_name="a", token_value="TOKEN-FOR-91"),
        ProxmoxInstance(host="10.0.0.92", user="u", token_name="b", token_value="TOKEN-FOR-92"),
    ]

    exported = full_config()
    exported.sites[0].proxmox = [  # same hosts, opposite order
        ProxmoxInstance(host="10.0.0.92", user="u", token_name="b", token_value="TOKEN-FOR-92"),
        ProxmoxInstance(host="10.0.0.91", user="u", token_name="a", token_value="TOKEN-FOR-91"),
    ]
    blob = export_config(exported, passphrase=None)

    result = import_config(blob, passphrase=None, current=current)
    by_host = {px.host: px.token_value for px in result.config.sites[0].proxmox}
    assert by_host == {"10.0.0.91": "TOKEN-FOR-91", "10.0.0.92": "TOKEN-FOR-92"}


def test_redacted_import_blanks_a_secret_with_no_counterpart():
    current = full_config()
    current.sites[0].proxmox = []  # the host in the export is unknown here
    blob = export_config(full_config(), passphrase=None)

    result = import_config(blob, passphrase=None, current=current)
    assert result.config.sites[0].proxmox[0].token_value == ""
    assert any("proxmox" in path for path in result.unresolved_secrets)


# ------------------------------------------------------------------- webui


def test_webui_is_never_exported():
    for passphrase in (PASSPHRASE, None):
        blob = export_config(full_config(), passphrase=passphrase)
        assert b"SESSIONSECRET" not in blob
        assert b"password_hash" not in blob
    # and it is absent from the decrypted payload, not merely absent from the text
    blob = export_config(full_config(), passphrase=PASSPHRASE)
    envelope = json.loads(blob)
    assert "webui" not in json.dumps(envelope.get("config", {}))


def test_import_keeps_the_targets_webui():
    """An imported password_hash + session_secret would be an instant admin handover."""
    current = AppConfig(webui=WebUIConfig(password_hash="MY-HASH", session_secret="MY-SECRET"))
    blob = export_config(full_config(), passphrase=PASSPHRASE)

    result = import_config(blob, passphrase=PASSPHRASE, current=current)
    assert result.config.webui.password_hash == "MY-HASH"
    assert result.config.webui.session_secret == "MY-SECRET"


# ------------------------------------------------------- format / versioning


def test_import_refuses_a_newer_config_schema():
    envelope = json.loads(export_config(full_config(), passphrase=None))
    envelope["config_schema"] = CONFIG_SCHEMA_VERSION + 1
    with pytest.raises(ConfigSchemaTooNewError):
        import_config(json.dumps(envelope).encode(), passphrase=None, current=AppConfig())


def test_import_refuses_a_newer_envelope_format():
    envelope = json.loads(export_config(full_config(), passphrase=None))
    envelope["format_version"] = 99
    with pytest.raises(UnsupportedFormat, match="newer than this build"):
        import_config(json.dumps(envelope).encode(), passphrase=None, current=AppConfig())


def test_import_rejects_a_foreign_file():
    with pytest.raises(UnsupportedFormat):
        import_config(b'{"hello": "world"}', passphrase=None, current=AppConfig())
    with pytest.raises(UnsupportedFormat):
        import_config(b"not json at all", passphrase=None, current=AppConfig())


def test_import_migrates_an_older_payload():
    """A schema-1 payload inside a current envelope is migrated, not dropped."""
    envelope = {
        "format": "netbox-monitor-config",
        "format_version": 1,
        "app_version": "1.0.0",
        "config_schema": 1,
        "encrypted": False,
        "config": {
            "schema_version": 1,
            "netbox": {"url": "http://nb", "token": "t", "default_site": "Home"},
            "technitium": {"url": "http://dns", "token": "legacy-token"},
        },
    }
    result = import_config(json.dumps(envelope).encode(), passphrase=None, current=AppConfig())
    assert result.migrated_from == 1
    assert [s.id for s in result.config.sites] == ["home"]
    assert result.config.sites[0].technitium.token == "legacy-token"


def test_peek_reads_the_header_without_a_passphrase():
    blob = export_config(full_config(), passphrase=PASSPHRASE, app_version="2.3.0")
    header = peek(blob)
    assert header["app_version"] == "2.3.0"
    assert header["encrypted"] is True
    assert header["config_schema"] == CONFIG_SCHEMA_VERSION
    assert "ciphertext" in header  # present, but unread


def test_export_filename_is_ascii_and_descriptive():
    name = export_filename("2.3.0", encrypted=True)
    assert name.startswith("netbox-monitor-config-2.3.0-encrypted-")
    assert name.endswith(".json")
    assert name.isascii()  # no RFC 5987 encoding needed in Content-Disposition
    assert export_filename("2.3.0", encrypted=False).count("redacted") == 1


# ------------------------------------------- the inventory must stay complete


def _model_secret_paths(model, prefix=()):
    """Every field in the AppConfig tree whose name smells like a credential.

    Mirrors how SECRET_PATHS addresses the *serialized* config: a list/dict of
    models contributes a "*" hop, an Optional model does not.
    """
    from typing import get_args, get_origin

    from pydantic import BaseModel

    pattern = re.compile(r"token|password|secret|community|passphrase|key", re.I)
    found = []
    for name, field in model.model_fields.items():
        annotation = field.annotation
        args = get_args(annotation)
        is_container = get_origin(annotation) in (list, dict, set, tuple)
        nested = next(
            (a for a in (annotation, *args) if isinstance(a, type) and issubclass(a, BaseModel)),
            None,
        )
        if nested is not None:
            step = (*prefix, name, "*") if is_container else (*prefix, name)
            found += _model_secret_paths(nested, step)
        elif pattern.search(name):
            found.append((*prefix, name))
    return found


# Fields that look like secrets but are not. Each needs a reason.
_KNOWN_NON_SECRETS = {
    ("sites", "*", "proxmox", "*", "token_name"): "names a token, doesn't authenticate",
    ("lldp", "secrets_private_key"): "a filesystem path, not key material",
    ("webui", "password_hash"): "webui is never exported",
    ("webui", "session_secret"): "webui is never exported",
}


def test_secret_paths_covers_every_secret_field_in_the_model():
    """A new credential field must be classified before it can ship.

    Without this, adding e.g. `api_key` to a config model would silently export it
    in cleartext in the redacted mode.
    """
    declared = {tuple(p) for p in SECRET_PATHS}
    allowed = set(_KNOWN_NON_SECRETS)
    unclassified = [
        path for path in _model_secret_paths(AppConfig) if path not in declared | allowed
    ]
    assert not unclassified, (
        f"secret-looking config fields are not classified: {unclassified}. "
        "Add each to SECRET_PATHS in config_transfer.py, or to _KNOWN_NON_SECRETS "
        "here with a reason."
    )
