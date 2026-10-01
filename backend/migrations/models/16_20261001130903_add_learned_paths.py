from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "learned_paths" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "path" VARCHAR(200) NOT NULL UNIQUE,
    "status" VARCHAR(16) NOT NULL,
    "hosts" JSONB NOT NULL,
    "hits" INT NOT NULL,
    "last_status" INT,
    "ai_verdict" VARCHAR(24),
    "first_seen_at" TIMESTAMPTZ NOT NULL,
    "last_seen_at" TIMESTAMPTZ,
    "decided_by" VARCHAR(255),
    "decided_at" TIMESTAMPTZ
);
COMMENT ON TABLE "learned_paths" IS 'A path the LLM proposed to smart_fuzz and a real request confirmed, that';"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "learned_paths";"""


MODELS_STATE = (
    "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"
)
