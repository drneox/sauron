from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "users" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "email" VARCHAR(255) NOT NULL UNIQUE,
    "password_hash" VARCHAR(255) NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "active" BOOL NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL,
    "last_login_at" TIMESTAMPTZ
);
        CREATE TABLE IF NOT EXISTS "auth_tokens" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "token" VARCHAR(128) NOT NULL UNIQUE,
    "created_at" TIMESTAMPTZ NOT NULL,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "user_id" INT NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE
);
        ALTER TABLE "scans" ADD "created_by" INT;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "scans" DROP COLUMN "created_by";
        DROP TABLE IF EXISTS "auth_tokens";
        DROP TABLE IF EXISTS "users";"""


MODELS_STATE = (
    "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"
    "9bugUqn8vWlo76L+vVIGvOpm9vI/2jiPMw=="
)
