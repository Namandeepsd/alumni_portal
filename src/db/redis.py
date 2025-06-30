import asyncio
from redis import asyncio as aioredis
from src.config import Config

JTI_EXPIRY=15

token_blocklist = aioredis.Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    username=Config.REDIS_USERNAME,
    password=Config.REDIS_PASSWORD,
    decode_responses=True
)

async def add_jti_to_blocklist(jiti:str)->None:
    await token_blocklist.set(
        name= jiti,
        value='',
        ex=JTI_EXPIRY
    )

async def token_in_blocklist(jti: str)->bool:
    jti = await token_blocklist.get(jti)

    return jti is not None