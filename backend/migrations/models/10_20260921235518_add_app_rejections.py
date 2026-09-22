from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "domains" ADD "app_rejections" JSONB;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "domains" DROP COLUMN "app_rejections";"""


MODELS_STATE = (
    "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"
)
