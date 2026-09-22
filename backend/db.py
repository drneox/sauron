# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""
Database layer — Tortoise-ORM models over PostgreSQL.
Connection string via DATABASE_URL env (defaults to local docker-compose Postgres).
"""
import os
import json

from dotenv import load_dotenv
from tortoise import Tortoise, fields
from tortoise.models import Model

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/asm")

TORTOISE_ORM = {
    "connections": {"default": DATABASE_URL},
    "apps": {
        "models": {
            "models": ["db", "aerich.models"],
            "default_connection": "default",
        },
    },
    "use_tz": True,
    "timezone": "UTC",
}


class Company(Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=255, unique=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    domains: fields.ReverseRelation["Domain"]

    class Meta:
        table = "companies"


class Domain(Model):
    id = fields.IntField(pk=True)
    # Nullable: scans launched without a company_name are parked under a
    # company-less domain row so they still get persistence and diffing.
    company = fields.ForeignKeyField("models.Company", related_name="domains", null=True)
    domain = fields.CharField(max_length=255)
    # Confirmed official app-store developers for the brand, e.g.
    # [{"store": "app_store", "name": "Apple Inc.", "artist_id": "284417353"}]
    app_developers = fields.JSONField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    scans: fields.ReverseRelation["Scan"]
    schedule: fields.ReverseRelation["Schedule"]

    class Meta:
        table = "domains"
        unique_together = (("company", "domain"),)


class Scan(Model):
    id = fields.CharField(pk=True, max_length=36)  # uuid4
    domain = fields.ForeignKeyField("models.Domain", related_name="scans")
    # full|discover|host — "host" scans evaluate a single host of the parent
    # domain and never count as the domain's "latest scan" for dashboards.
    kind = fields.CharField(max_length=16, default="full")
    # Actual scan target (host string for host scans, apex otherwise); the FK
    # above always points at the parent apex domain.
    scan_target = fields.CharField(max_length=255, null=True)
    status = fields.CharField(max_length=20)  # queued|running|completed|failed|interrupted
    progress = fields.IntField(default=0)
    current_module = fields.CharField(max_length=64, null=True)
    started_at = fields.DatetimeField()
    completed_at = fields.DatetimeField(null=True)
    scorecard = fields.JSONField(null=True)
    result = fields.JSONField(null=True)
    # Audit: id of the user who launched the scan (null = scheduler/dev mode)
    created_by = fields.IntField(null=True)

    class Meta:
        table = "scans"


class Subdomain(Model):
    id = fields.IntField(pk=True)
    domain = fields.ForeignKeyField("models.Domain", related_name="subdomains")
    subdomain = fields.CharField(max_length=255)
    first_seen_scan_id = fields.CharField(max_length=36)
    last_seen_scan_id = fields.CharField(max_length=36)

    class Meta:
        table = "subdomains"
        unique_together = (("domain", "subdomain"),)


class Endpoint(Model):
    id = fields.IntField(pk=True)
    domain = fields.ForeignKeyField("models.Domain", related_name="endpoints")
    path = fields.CharField(max_length=1024)
    source = fields.CharField(max_length=1024, default="")
    first_seen_scan_id = fields.CharField(max_length=36)
    last_seen_scan_id = fields.CharField(max_length=36)

    class Meta:
        table = "endpoints"
        unique_together = (("domain", "path"),)


class Asset(Model):
    id = fields.IntField(pk=True)
    domain = fields.ForeignKeyField("models.Domain", related_name="assets")
    # subdomain|ip|endpoint|technology|admin_panel|exposed_file|port|app|neighbor
    type = fields.CharField(max_length=32)
    value = fields.CharField(max_length=1024)
    metadata = fields.JSONField(null=True)
    first_seen_scan_id = fields.CharField(max_length=36)
    last_seen_scan_id = fields.CharField(max_length=36)
    first_seen_at = fields.DatetimeField(auto_now_add=True)
    last_seen_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "assets"
        unique_together = (("domain", "type", "value"),)


class Finding(Model):
    """Persistent remediation-tracked finding. Scans are ephemeral; a Finding
    row survives across scans, keyed by a stable fingerprint
    (domain + module + normalized finding text), and carries a lifecycle
    status (open|accepted|fixed) plus compliance-framework tags."""
    id = fields.IntField(pk=True)
    domain = fields.ForeignKeyField("models.Domain", related_name="findings")
    fingerprint = fields.TextField()  # sha1(domain|module|normalized text)
    module = fields.CharField(max_length=64)
    text = fields.TextField()
    risk = fields.CharField(max_length=16)  # critical|high|medium|low
    category = fields.CharField(max_length=32, default="info")  # vulnerability|misconfiguration|exposure|info
    frameworks = fields.JSONField(default=list)  # e.g. ["NIST-CSF", "ISO-27001"]
    status = fields.CharField(max_length=16, default="open")  # open|accepted|fixed
    first_seen_scan_id = fields.CharField(max_length=36)
    last_seen_scan_id = fields.CharField(max_length=36)
    first_seen_at = fields.DatetimeField()
    last_seen_at = fields.DatetimeField()
    fixed_at = fields.DatetimeField(null=True)
    notes = fields.TextField(default="")

    class Meta:
        table = "findings"
        unique_together = (("domain", "fingerprint"),)


class AssetHistory(Model):
    id = fields.IntField(pk=True)
    asset = fields.ForeignKeyField("models.Asset", related_name="history")
    scan_id = fields.CharField(max_length=36)
    changed_at = fields.DatetimeField(auto_now_add=True)
    old_metadata = fields.JSONField(null=True)
    new_metadata = fields.JSONField(null=True)

    class Meta:
        table = "asset_history"


class User(Model):
    id = fields.IntField(pk=True)
    email = fields.CharField(max_length=255, unique=True)
    password_hash = fields.CharField(max_length=255)  # salt_hex$pbkdf2_hex (see auth.py)
    role = fields.CharField(max_length=16, default="viewer")  # viewer|operator|admin
    active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    last_login_at = fields.DatetimeField(null=True)

    tokens: fields.ReverseRelation["AuthToken"]

    class Meta:
        table = "users"


class AuthToken(Model):
    id = fields.IntField(pk=True)
    token = fields.CharField(max_length=128, unique=True)
    user = fields.ForeignKeyField("models.User", related_name="tokens", on_delete=fields.CASCADE)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "auth_tokens"


class Schedule(Model):
    id = fields.IntField(pk=True)
    domain = fields.OneToOneField("models.Domain", related_name="schedule")
    interval_hours = fields.IntField()
    enabled = fields.BooleanField(default=True)
    agent_mode = fields.BooleanField(default=False)
    last_run_at = fields.DatetimeField(null=True)
    next_run_at = fields.DatetimeField(null=True)
    # Dual-track scheduling: asset discovery runs on its own recurrence,
    # independent of the full vulnerability scan above.
    discover_enabled = fields.BooleanField(default=False)
    discover_interval_hours = fields.IntField(null=True)
    next_discover_at = fields.DatetimeField(null=True)

    class Meta:
        table = "schedules"


class _StrJSONField(fields.JSONField):
    """JSONField that also accepts plain (non-JSON) Python strings.

    Stock JSONField treats a str as pre-serialized JSON and rejects values like
    "new"; settings values may legitimately be plain strings (chain_eval_scope).
    """

    def to_python_value(self, value):
        if isinstance(value, (str, bytes)):
            try:
                json.loads(value)
            except (ValueError, TypeError):
                return value if isinstance(value, str) else value.decode()
        return super().to_python_value(value)

    def to_db_value(self, value, instance):
        if isinstance(value, str):
            try:
                json.loads(value)
            except (ValueError, TypeError):
                value = json.dumps(value)
        return super().to_db_value(value, instance)


class AppSetting(Model):
    # Singleton-style key/value store for admin-editable app settings.
    key = fields.CharField(pk=True, max_length=64)
    value = _StrJSONField()
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "app_settings"

async def init_db() -> None:
    # _enable_global_fallback: Tortoise 1.x scopes connections per-task by default;
    # our queue workers and scheduler run in their own asyncio tasks.
    await Tortoise.init(config=TORTOISE_ORM, _enable_global_fallback=True)


async def close_db() -> None:
    await Tortoise.close_connections()
