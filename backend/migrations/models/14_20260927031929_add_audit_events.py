from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "audit_events" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "created_at" TIMESTAMPTZ NOT NULL,
    "user_email" VARCHAR(255) NOT NULL,
    "action" VARCHAR(64) NOT NULL,
    "target" VARCHAR(255),
    "detail" JSONB,
    "ip" VARCHAR(45),
    "user_id" INT REFERENCES "users" ("id") ON DELETE SET NULL
);
COMMENT ON TABLE "audit_events" IS 'Who-did-what trail for sensitive in-app actions (logins, user';"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "audit_events";"""


MODELS_STATE = (
    "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"
    "s7DbVWssC6i9nz/wE+fr6Y"
)
