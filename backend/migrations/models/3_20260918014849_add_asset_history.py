from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        CREATE TABLE IF NOT EXISTS "asset_history" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "scan_id" VARCHAR(36) NOT NULL,
    "changed_at" TIMESTAMPTZ NOT NULL,
    "old_metadata" JSONB,
    "new_metadata" JSONB,
    "asset_id" INT NOT NULL REFERENCES "assets" ("id") ON DELETE CASCADE
);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        DROP TABLE IF EXISTS "asset_history";"""


MODELS_STATE = (
    "eJztXFtvozgU/isRT11pd5Smncxo35I2VbszbVZN9qIZjZBD3ASVmAyYttFs//va5mbAUC"
    "4hAcYvTWL7GPwdY3/f8aE/lI25hIb9bmTbECu/934oCGwg+RKt+LWngO02LKYFGCwM1hLQ"
    "JqwILGxsAY129AAMG5KiJbQ1S99i3USkFDmGQQtNjTTU0SoscpD+3YEqNlcQr6FFKr5+Je"
    "02QEfsYrstpJ9PwHCg8u0b+aqjJXyBNm1Jf24f1QcdGsvIIPQlNWLlKuuClN0gfMUa0htZ"
    "qJppOBsUNt7u8NpEQWsdsdGvIIIWwJB2jy2HjozeuAeBP1h3EGET9xY5myV8AI6BOSQWal"
    "imqOrddK7OJnNVVQpgp5mI4k5u1WajX9Fb+G1wev7h/OPZ8PwjacJuMyj58OpeOgTGNWTw"
    "3M2VV1YPMHBbMIxDUH1fRGG9WANLjKvfPoYsueU4sj6OWdD6BSG24VQ7BLgb8KIaEK3wmv"
    "w8G2Qg+ffo/uJ6dH9yNviFXtAkT4b7wNx5NQNWRcEOwXUneAF0A4MOwnvaH5znAJg2S4XY"
    "rYyCvIEY0OmdxPmP2fROjDNvE4N6qWu491/P0O3EWiGA3FsKmoJ4Br4UDNrzxra/GzyqJ7"
    "ejf+OAX3yejhk2po1XFuuFdTCOYf+gWzZWbQiRamsAqaIlOn22i607OPXPhnlWlmH6yjKM"
    "T3oDVMBdaCxhzwE7N2MBTkJ+SZDC+ga+Od1d4/jK41m/87+00QEWBMspMnbe2pjhgPnN7W"
    "Q2H93+GVmVLkfzCa0ZsNJdrPQk7qygk94/N/PrHv3Z+zK9m8QXr6Dd/ItC7wk42FSR+ayC"
    "Jcfo/FIftZRHrrjr47bS803xvI8R53rv7kPPu8pFuMim6o+IzdsypA0O3oMSodru4VEoRE"
    "J5GEX4yrSgvkKf4I4BfUPuCSBNRJI9kXsZdNQygF/9OeSXhguTBZ4DQRydWmT8ZNQQu1v+"
    "aHYxupwoDOcF0B6fgbVUUwBfE4ZrWrsk4mPP8OrTPTQAG0Uq2CyicB321BHIGYDmwOSAi0"
    "CarNoMNvESgMCKDYlem15JhFlalIbD9I1gjco5cr8xGxmYOWJgpgSvl2y+GJvX1gCRJ7QE"
    "n4taSjbXFDaXh8ebZARlYkZxOxk3Kh83QvC5lA/idtIH5X3gkodCezdvIjXN25oG+OdtFS"
    "VNcG7XMnjzKhp+XhUVNHUy9QtzswVISNL9qkx+rrFGOqzhPFVy8yNyc/ZZgJj77ffDyo8L"
    "bYSTD96/z0HKSatUVs7qYrSccE9cjpZHLCUtbzotT2ydeeJWbvjLrha3yh0kbCZJPGzAyg"
    "NLsAuGMKZvgpy/9p1SpIWbsBc+lslEx9wX02L46TtjaNHBiJXcHeXuWGF3jHjdXemKyfWo"
    "USnB3rDtr2a9zu0nFRU7Jw/bhXBeyR6dW+VPIcN844qHkC1cr1LJHP/kQ7TcmsyiEkYTr5"
    "uuwkTPvipCNCNddBYeZ7EX3TTz++kSUIW0Ez/l1nDpGIJIkI/oFMG5Sf7kmXthX93YMF4L"
    "isxggRLITH7xSheakZWyvrdXtoCQe6kzj6kzmQsSsKarTL99BzVmXW9V2KZjaYWC3KHF4W"
    "BWlFaDLF+fkK9P/Eywy0Tqfe2OMpH62InUdR64MCUq4MG+Qk3nwIEMbk62QfpCus+Vs0GH"
    "4vtaNzNygzHAjkDJZ5CzwKKDG9Wgn+eYpZ9+ytKPb1Rby6TBewHEqfsUb3K4barf4D0qcn"
    "7hWBZEWCVLljBikj5zk5alZnDDoibRCTzMoy6G6dpimJRvGFjlTgmjlh08JWzJqaCPyZvH"
    "gpSzlDoOjtnuwdUNe8i65GlbI/RdI8wy6eb0dPmIkcyVL58rT6ro/ReAPrSQuJfHXQYM9k"
    "XGZMCg2wED7/hQGDQIjxazAgduq4YFD+RRWcWjMnIdaD0BQ12bjlVEzyYN5VoqELYQ0YEK"
    "Zu7YNA0IkBhcziqG6oKY1QWrP68PSwzG0+nnCDEY38xjdOCv2/Hk/uSUsQTSSHfX1CTYZP"
    "FzIwGinIssvKOGB4Q8KGkt5uy0y3JK/9ej0FQKzCYLTARfyvo5Zir93GQ/N0RStZ50FXh3"
    "Lcn83xZffupg7dLrqI6oS3hVE1NBjqtITfEJsBlyKpJvW18yYnAdmZF43P/WxE+L3IeyvF"
    "EXz2XreP9N5szJnLmfCfaG8LVjoyxD4O1kYgcLgY+gpWtrEWXzajL5GgjbyNh3mx7qLFL2"
    "BC3be+sq7z7FmXRwd6qFkNGHqgDCXvMOonvaz5OHSFplvCOSyEQkV8QQFUo94Ewq5R40De"
    "1DJB9UiupU3cxe/wcHDJO5"
)
