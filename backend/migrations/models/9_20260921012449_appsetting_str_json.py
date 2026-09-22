from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "app_settings" ALTER COLUMN "value" TYPE JSONB USING "value"::JSONB;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "app_settings" ALTER COLUMN "value" TYPE JSONB USING "value"::JSONB;"""


MODELS_STATE = (
    "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"
    "j6TS/nmT++ESO9vis1UGfNvJ7Pn/fKhy1w=="
)
