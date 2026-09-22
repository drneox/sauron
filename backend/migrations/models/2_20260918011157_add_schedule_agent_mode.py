from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "schedules" ADD "agent_mode" BOOL NOT NULL DEFAULT False;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "schedules" DROP COLUMN "agent_mode";"""


MODELS_STATE = (
    "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"
    "v/AZJadAM="
)
