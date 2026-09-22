from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "findings" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "fingerprint" TEXT NOT NULL,
    "module" VARCHAR(64) NOT NULL,
    "text" TEXT NOT NULL,
    "risk" VARCHAR(16) NOT NULL,
    "category" VARCHAR(32) NOT NULL,
    "frameworks" JSONB NOT NULL,
    "status" VARCHAR(16) NOT NULL,
    "first_seen_scan_id" VARCHAR(36) NOT NULL,
    "last_seen_scan_id" VARCHAR(36) NOT NULL,
    "first_seen_at" TIMESTAMPTZ NOT NULL,
    "last_seen_at" TIMESTAMPTZ NOT NULL,
    "fixed_at" TIMESTAMPTZ,
    "notes" TEXT NOT NULL,
    "domain_id" INT NOT NULL REFERENCES "domains" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_findings_domain__647483" UNIQUE ("domain_id", "fingerprint")
);
COMMENT ON TABLE "findings" IS 'Persistent remediation-tracked finding. Scans are ephemeral; a Finding';"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "findings";"""


MODELS_STATE = (
    "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"
)
