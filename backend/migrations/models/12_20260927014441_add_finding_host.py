from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "findings" ADD "host" VARCHAR(255);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "findings" DROP COLUMN "host";"""


MODELS_STATE = (
    "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"
)
