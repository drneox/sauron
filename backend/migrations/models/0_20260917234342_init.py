from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "companies" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "name" VARCHAR(255) NOT NULL UNIQUE,
    "created_at" TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS "domains" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "domain" VARCHAR(255) NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL,
    "company_id" INT REFERENCES "companies" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_domains_company_78c240" UNIQUE ("company_id", "domain")
);
CREATE TABLE IF NOT EXISTS "endpoints" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "path" VARCHAR(1024) NOT NULL,
    "source" VARCHAR(1024) NOT NULL,
    "first_seen_scan_id" VARCHAR(36) NOT NULL,
    "last_seen_scan_id" VARCHAR(36) NOT NULL,
    "domain_id" INT NOT NULL REFERENCES "domains" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_endpoints_domain__b3afba" UNIQUE ("domain_id", "path")
);
CREATE TABLE IF NOT EXISTS "scans" (
    "id" VARCHAR(36) NOT NULL PRIMARY KEY,
    "status" VARCHAR(20) NOT NULL,
    "progress" INT NOT NULL,
    "current_module" VARCHAR(64),
    "started_at" TIMESTAMPTZ NOT NULL,
    "completed_at" TIMESTAMPTZ,
    "scorecard" JSONB,
    "result" JSONB,
    "domain_id" INT NOT NULL REFERENCES "domains" ("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "schedules" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "interval_hours" INT NOT NULL,
    "enabled" BOOL NOT NULL,
    "last_run_at" TIMESTAMPTZ,
    "next_run_at" TIMESTAMPTZ,
    "domain_id" INT NOT NULL UNIQUE REFERENCES "domains" ("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "subdomains" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "subdomain" VARCHAR(255) NOT NULL,
    "first_seen_scan_id" VARCHAR(36) NOT NULL,
    "last_seen_scan_id" VARCHAR(36) NOT NULL,
    "domain_id" INT NOT NULL REFERENCES "domains" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_subdomains_domain__453892" UNIQUE ("domain_id", "subdomain")
);
CREATE TABLE IF NOT EXISTS "aerich" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "version" VARCHAR(255) NOT NULL,
    "app" VARCHAR(100) NOT NULL,
    "content" JSONB NOT NULL
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        """


MODELS_STATE = (
    "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"
)
