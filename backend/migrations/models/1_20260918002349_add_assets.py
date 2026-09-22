from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "assets" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "type" VARCHAR(32) NOT NULL,
    "value" VARCHAR(1024) NOT NULL,
    "metadata" JSONB,
    "first_seen_scan_id" VARCHAR(36) NOT NULL,
    "last_seen_scan_id" VARCHAR(36) NOT NULL,
    "first_seen_at" TIMESTAMPTZ NOT NULL,
    "last_seen_at" TIMESTAMPTZ NOT NULL,
    "domain_id" INT NOT NULL REFERENCES "domains" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_assets_domain__aab5b3" UNIQUE ("domain_id", "type", "value")
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "assets";"""


MODELS_STATE = (
    "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"
)
