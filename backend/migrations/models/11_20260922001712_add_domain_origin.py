from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "domains" ADD "origin" VARCHAR(16) NOT NULL DEFAULT 'manual';"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "domains" DROP COLUMN "origin";"""


MODELS_STATE = (
    "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"
    "xsi89WGfBtJ7Pn/wMjGmGE"
)
