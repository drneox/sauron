from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "app_settings" (
    "key" VARCHAR(64) NOT NULL PRIMARY KEY,
    "value" JSONB NOT NULL,
    "updated_at" TIMESTAMPTZ NOT NULL
);
        ALTER TABLE "domains" ADD "app_developers" JSONB;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "domains" DROP COLUMN "app_developers";
        DROP TABLE IF EXISTS "app_settings";"""


MODELS_STATE = (
    "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"
    "tcrf24b2Nurfa2XA6xqzl/8BxG4BqQ=="
)
