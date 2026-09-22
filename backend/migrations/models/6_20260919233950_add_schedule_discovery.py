from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "schedules" ADD "discover_enabled" BOOL NOT NULL DEFAULT False;
        ALTER TABLE "schedules" ADD "discover_interval_hours" INT;
        ALTER TABLE "schedules" ADD "next_discover_at" TIMESTAMPTZ;"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "schedules" DROP COLUMN "discover_enabled";
        ALTER TABLE "schedules" DROP COLUMN "discover_interval_hours";
        ALTER TABLE "schedules" DROP COLUMN "next_discover_at";"""


MODELS_STATE = (
    "eJztXVtvnDgU/ivRPGWlbJVM0jTat8mlarZNZpVMd1etKuQBZwaFMRRMLurmv69tbgZswm"
    "WYAeKXNrF9DHzHnPOdc2zya7SyDWh57yaOcwsxNtFi9MfOrxECK0h+EPTu7YyA4yR9tAGD"
    "ucWGkx7NCwayDjD3sAt0TPrugOVB0mRAT3dNB5s2Iq3ItyzaaOtkYHDxsMlH5k8fatheQL"
    "yELun4/oM0m8iAT9CLfnXutTsTWkbqpu/hM70469Dws8Maz5bA/ciG0uvNNd22/BXihjvP"
    "eGmjeDy5H9q6gAi6AEODewR6h+ETR03B3ZIG7Powvk0jaTDgHfAtzD3yXEvaRpp2PZ1ptx"
    "czTRtVAEm3EQXYRNhjCKzAk2ZBtMBL8uvx0UtwnQSIYBS94N+Tm7NPk5vd46Pf6AVtoqVA"
    "hddhz5h1vbApAAbBJAz3BOgHYJGHzkH95+30Wgx1LJAB2zB1vPPfjmV6uA7oUUOCerLaNg"
    "B7AcwUCjrzyvN+Wjy8u1eTf7PIn32ZnjJwbA8vXDYLm+CUqSGB3XcMCo4GcB77c9KDzRUU"
    "45+WzCohFH0X/dBDVYxcCIwpsp7DN69ANbPLq4vb2eTqr5R+ziezC9ozZq3Pmdbd44zO4k"
    "l2/rmcfdqhv+58m15fZNUYj5t9G9F7Aj62NWQ/asDgMYqao7unJu7unnv3aMMc6PePwDW0"
    "XI89tmVj812r8SrbAhBYMJ1RcOltRubfI0Zd6BdYR7FLoENacAbfybgV0Tu7GF3Be5F5+V"
    "HWT5hG/v25RFj86gSDM68MWXbZlyS09931EQt6C7+PD44+HJ0cHh+dkCHsNuOWDwUvzeX1"
    "7BWfEOmirPeNxq/H/W7b/KQc8OG4hAM+HEsdMO1KW36Jw5WjK3O4Q4D3YH9chuHQYVKIg8"
    "40yCuIAV3eVYgNL9OI24SmoCuIb5ra3Jmuh0kIAZHm6QBpIhMtX+1i6QEu/cPjMpYlS1Y4"
    "y3KcXfQWaIC7UFjBXgJ2bsVWZ/M5YUXou0LoQzPO8XmGmuSVq676rKzSfFc0LwvleM0HkY"
    "vQyErjj5TM62FIHxS8hkgkFyBnQc4j/NF2oblAn+EzA/qS3BNAuogkh0HueTxRzwB+idZQ"
    "1JoYJhc8xgFxemmR5ydPDXHg8ie3Z5Pzi9GLPO+QAL4kDNd2BanX01Dw4+cbaAH2FFKwWU"
    "bhUzLTQCB/aT09E2Emy9JwmL6SrNE4RW4nga8SMy0kZmrwesXmq7F5fQnQolZiPi2p2FxX"
    "2FwZHm+TJ6iTM8rKqbxR/bwRgo+1dJCVUzqor4OAPFTy3byIimlej2lAVG9rGNLEdbuewV"
    "s2ouHXVdWAplWm7uPlzL6HaCSi6XFnMUcnwwirJuO2uMVGMfQ2SqeR8kvXTiOBwe1dOhif"
    "lCntjU/klT3al6HnhIPW2zeTllT0vE/0HD45JpmthtbTkgPUek+0LEip59Xse9CtRj45Cc"
    "U9X+eeFK41UM+v4TQ9A7cs8+QWVZeI55m9cgASZoejrkLSqbNBJlSUc1iUk/1fgXFG4wdH"
    "OMfv35cgnGSUlHCyPkU43ybhrLBRO1uh9poVTEtXp7uZndxspTQES+AFExjlTpDT17r3su"
    "uJEw73Lahd7Nv0i7LNI3LPmEgMsFTainekhwUN+AAt24GuwArKqzZ5SVW3qV+3USzlrbCU"
    "lNYDj1MtZZIWqpU16djL1nLShPPrDfMmXJjeL4TLZk7Sa6v+NsTkwGHDXYg9tFdSUp1KiC"
    "PDsZlEI4wuwmmGChPd/NYQolsyxWDh8edriV9vo3mGBFSlGJZfckto+JYgIxchOkVwZpN/"
    "yqy9ZK5hOIyXisF+bKAE4T5vvOQBf8pStnd83QEkyFLx/jbjfaaCHKzyaD8aP8BYv61j1Z"
    "7tu3qlYkMisTmYR6Neg6zOT6vz028JdnWScl3eUZ2k3PZJyjYLXywSFfDgKEKVc+A4DO7O"
    "rg+5IV2n5ezQ5oR12c2Cw4EYYF8QyReQs1higI5qvF+m3LUvr3btZx2V49o0eS+AWOqneJ"
    "HNuan9DvuoVP3Cd12IsEZMljBjIl+5eclaK7hjWZN2vv2ZshBuvSphWnKAVcKeVAVLbaOm"
    "VRjKWWqVgzOya1B1x16yIWna0wl91wmzzKtZvvMiJaQ2XdTfdEG66P1XgD6RULg33+wyF9"
    "Tk5dseUkJq20Oejak8zLpQVXmYYedhwqqsMBeTVGyL8jHBqI7lZFQFsmEFklwHug/A0pa2"
    "L9oNKwc4J6hsqcBDQUQfVLByT23bggCJweWkMqjOiVhbsEbrerN863Q6/ZLiW6eXswzL+n"
    "p1enGze8DIFxlkBjY1DzYxfkGCRbSVpQjvtOAGIY9beos5KyK6fu2vySaiKm7vctyO4FNd"
    "PWdElZ67rGfD9HT7AbpaPc8lElf2tII9jQGszcwKZlA5hDzgzDrFmNW0bhl5ZeI6beK6kT"
    "XqfVxZ4fR5Prnxen4p2nTeenZpq4poK7fULF8Un44QJYz4oxMFGaPUSY32trHH11F72bf7"
    "oW9+WZTezsMLDXFHTxsn2NVua7Xb+i3B3hG+tm2UVZWvn0xsY1U+9o1DAWGLvn0o52r084"
    "GqsjcsPgbJKrWqOKhYYHAb2VthYQ7wvEebvLNL4FU8xJkRHCAJaAVx16624zoav8FjnA8m"
    "fAyM7QYOc5YhWgdyonWQI1rE8JsPlWunsZAqVZdP86uvX8lX+XC/fsViQMtemLXL5bywqj"
    "J0rcpQISOe+fsbTb8cxf8Rl56974UfXmntT+JA19SXI0G0FPbsFf4xnGSMCpg25hdaDpge"
    "SAwcvmRlGSYnokh86c+vVkE4HD5AdA/2y5z2JaMKvsSSO+9LroghqnTAhxNpdMKna2hv4o"
    "hPowp4U2f28j9Hg5Q3"
)
