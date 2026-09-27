from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "findings" ADD "evidence" JSONB;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "findings" DROP COLUMN "evidence";"""


MODELS_STATE = (
    "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"
)
