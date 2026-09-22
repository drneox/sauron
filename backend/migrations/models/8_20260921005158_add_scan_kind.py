from tortoise import BaseDBAsyncClient

RUN_IN_TRANSACTION = True


async def upgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "scans" ADD "kind" VARCHAR(16) NOT NULL DEFAULT 'full';
        ALTER TABLE "scans" ADD "scan_target" VARCHAR(255);"""


async def downgrade(db: BaseDBAsyncClient) -> str:
    return """
        ALTER TABLE "scans" DROP COLUMN "kind";
        ALTER TABLE "scans" DROP COLUMN "scan_target";"""


MODELS_STATE = (
    "eJztXW1v2zgS/iuCP6W4NEjcbra4OxzgpOk1t22yaLwv2O1CoCXaFiyTWorKy27z34+kLI"
    "l6oS3Jliwr/NLG5AwlPUORz8yQ1N+DJbah65+MPO8OUuqg2eCfxt8DBJaQ/VFQe2wMgOcl"
    "dbyAgokrxFmN6YeCogJMfEqARVndFLg+ZEU29C3ieNTBiJWiwHV5IbaYYHjxVVGAnD8DaF"
    "I8g3QOCav4/Q9W7CAbPkI/+uktzKkDXTt10wv4xC8uKkz65InCyzkgH4Qov97EtLAbLJEk"
    "7j3ROUaxPLsfXjqDCBJAoS09Ar/D1RNHReHdsgJKAhjfpp0U2HAKApdKjzwxk7KBad7cjs"
    "27q7FpDiqAZGHEAXYQ9QUCS/BouhDN6Jz9PH/7HF4nASKU4hf8efTl8uPoy9H521f8gphZ"
    "KTThzapmKKqeRROAgrARgXsC9D1w2UPnoP7f3e1NMdSxQgZs27Go8c1wHZ/WAT0qSFBPel"
    "sLsK+BmUPBW176/p+uDO/R59GvWeQvP91eCHCwT2dEtCIauBBmSGAPPJuDYwKax/49q6HO"
    "Ehbjn9bMGmGlehL9cYCmGBAI7FvkPq3evDWmGV9/vrobjz7/mLLP+9H4itcMRelTpvToPG"
    "OzuBHjl+vxR4P/NH67vbnKmjGWG/824PcEAopNhB9MYMsYRcXR3fMhbrqQ3j1eMAHW4gEQ"
    "28zV4CFWyearlsNltgQgMBM24+Dy24yGf58N6oXzgqhYPyVwkQYmg9+Z3JLZXVyM9+DjaH"
    "j5o+w84dj59+ca0eJXJxTOvDKs22VfktV43905YsZv4fXw7O33b9+9OX/7jomI24xLvl/z"
    "0lzfjDfMCZEtys6+kfxupt99Dz+pCfjNsMQE/GaonIB5VXrkV0y4anRVE24f4D07HZZhOF"
    "xMCXFYmQZ5CSng3bsKsZF1tuI2q6GgK4i3TW2mDvEpcyEgMn0LILNoiFb39mLtHnb9N+dl"
    "RpYsWZFGlvNsp3fBFrgXKmvYS8Au9djqbD6nrAl9Vwj9ahiX+LxATfHKVTd9VldbviuWV7"
    "lysuVDz6VwkFX6HymdzW7IIRh4B55IzkHOgpxH+AMm0JmhH+CTAPqa3RNAVhFJXjm57+OG"
    "Dgzg56gPRaXJwETAQ+wQp7sWe3721JCGU/7o7nL0/mrwrI47JIDPGcPFpCD0erFS/PDDF+"
    "gC8RRKsEVE4WPSUk8gf248PBNhporSSJhuCNaYkiH3E8DXgZkGAjM1eL1m89XYvDUHaFYr"
    "MJ/W1GyuK2yuDI/H7AnqxIyyejpuVD9uhOBDLRtk9bQN6tsgJA+V5m5ZRfs0m30aEOXbtn"
    "Rp4rzdgcFb1qOR+1VVh6ZRph7Q+RgvIBoU0fS4cj1HZ2KMVTO5PS6x0Qy9idRpZPzSudNI"
    "oXdrl86G78qk9obv1Jk9Xpeh54yD1ls3k9bU9PyQ6Dl89BzWWg2rpzV7aPUDsXJBSD1v5s"
    "CHpBr5lDQ099zMPTlcO6CeP62aOTBwyzJPqVN1iXhe4qUHUGF0OKpaSzotIeRATTn7RTnF"
    "/xUYZyTfO8I5/O67EoSTSSkJp6jThPNlEs4KC7WzGWp/u4Rp6ex0N6OT7WZKV2AVzIIJjO"
    "pJULLXrteyW8kkvFq3oFex73NeVC0eUc+MiUYPU6WNzI58s6AN76GLPUgKRkF11iavqfM2"
    "9fM2mqW8FJaSsno441QLmaSVakVNOvayNRw0keb1LeMmkpt+WAiXjZyk+1b9ZYjJhsMtVy"
    "Ee4HilJNWpgDiyPSw0tsLoatVMX2GaspuLzjGoj9KHsJW+gsRXCG6J0B1rorfwBJOdOPl3"
    "UTt9AqqSoy93uTm0A7cgbBkheovgGLN/yvS9pK1+zKrPFSMi8SheEBORR3h1VCQ1nTS3x9"
    "8DzBPVQZF9BkWECXKwqkMikXwPAyJN7T33cUCsShmZRKM9mAeDgwZZbzLf0/4Ivcl8L7Dr"
    "7aa7mh31dtN9bzdtMjsY+eoFVFhy49VMWI4YbCTCgx8h8R2fQkQNApfQdoSv8pprLaBtrB"
    "o7Mbh/7BuAQAN6cyZIgPsvAxjSHcmm2VGzXxHBD4YfkHvnHjIxi2DfN4S3f2ws4BNrafLE"
    "xH3x8LzVGSQeuwf6FR2FBjb+YTCMmHPF/kCYLIHr/JXcgEHhI311bABkGxYgxOFXMVxnCq"
    "0nNqR95a8JDXzjCHsQfQOWBT32InybOqxjvzI8l1XxgKHr8Jfp9ZQwcz1gsjAomPkng83u"
    "hHTH2qvYq1chWyKH7pj1EhUNS6n1ggisSy9d/Tpen/mLs0ufbm/+G4ln04GZk65wcSBFTc"
    "ISjV4A3syBqdKODtZ9q3TqSL4X4Lbdm4njL6r05Ui+F2BnPOcyPsSZ2oc4y29tZ1DMCk/3"
    "UAMs67QYnHDQFLcToNj9AY8xkam0Hiat1f7ZyoN/TwNkcSyNSeC41EH+Cb/ef5oyQ9tLZE"
    "IyWiksF2u02PM5V24pNLfzAUYH5XRQ7iXBrk9+fEGbE/VRjy/G1CJCVeuVftzlStpuLlfo"
    "hYURprCAC6q9+lihBxnatp16nbsa6NyVzl0NNuWuxCrKgsRVtLpSnbWKl3B2Z1u32t/YpY"
    "PRod3Hu3Iv1FmWBXvMKkBH8i1OWVPWwKFGL4T3SwGZFR3PtuGA1UStFtgdY3otbBw8jGhc"
    "exifloH4VI3waRZgj2BOmAsgVnIuWaU9ynXaYb6Vyp4EhEBEzeoJ17xm/waJ3edd2ftO6m"
    "1pTWvqWEunPXGxAgjW3Luc0dUxly5b2reYK2oxLylvZnVaNKWkTwion/5kVfz+K0CfaGjc"
    "tz+ZYVKw7EK9Rz+lpPfo59mYjinuClUdU+x3THG1O7YwrpjsnF0XWwylOhZf1Gu2t1yzza"
    "4DyT1wzTkOio5uUgOcU9RjacEMBRF/0IKee4GxCwEqBlfSyqA6YWpNwRr163b51sXt7acU"
    "37q4zmYTf/p8cfXl6EyQLybkhGNqHmw2+IUBlqIjBdbhnVZsEfK45GAxF4taSFB7PUyiqv"
    "32LvvtCD7WtXNGVdu5y3a2Hd/C95CY9WauInU9nlYYT2MAazOzNS3oGEIecDE6xZjVHN0y"
    "+nqI6/QQ142o0cH7lbmYUZXgxub4UnT4V+PRpb0aoqnY0nbxoviUuqKAkXyE3ZqIUerEvO"
    "aOE4uvo3f/7/er1HK3KL2cR1bq44qeJlZN6Q12eoPdS4K9I3xt3yjrLN9hMrHWsnzig3wF"
    "hC36UJ+aq/Fv3enMXr/4GGS91K0yQcUKvduU0QgL84DvP2D2zs6BX/Ew3YxiD0lAI4gTXG"
    "3FdSTf4s6Xewc+hIPtIe59YQO/c185dxor6VR1+TC//lSTupf391NNwgd08cypnS6XlXWW"
    "oWtZhgoRceloQbyA235WZBTQ+Zi3c4Dvu8rvavT7oSNIHGs+KPCWVjXH6/wlkMhoh6m1ea"
    "Fhh+men7eMK4WvJRVN4kt/K7QKwivxHqJ7dlpmty+TWvNFjNx+X3ZFfmB4HmH1Bh9Jpf3z"
    "JvfDJXa2xWerDPi2k9nz/wGzzXE/"
)
