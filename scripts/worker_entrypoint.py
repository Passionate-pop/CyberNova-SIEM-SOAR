import asyncio
from cybernova.pipeline.device_processor import device_event_processor
from cybernova.database.postgres.session import init_db
from cybernova.database.redis import get_redis


async def main():
    await init_db()
    print("Worker DB initialized")
    redis = await get_redis()
    if redis:
        print("Worker Redis connected")
        await device_event_processor.start()
        print("Worker started")
    else:
        print("Worker started without Redis")


asyncio.run(main())
