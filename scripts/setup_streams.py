"""
CyberNova — Setup Redis Streams Consumer Groups
Run: python scripts/setup_streams.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybernova.config.settings import get_settings
from cybernova.streaming.streams import ALL_STREAMS, CONSUMER_GROUPS, STREAM_PREFIX

import redis.asyncio as aioredis


async def main():
    settings = get_settings()
    redis = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password or None,
        protocol=2,  # RESP2 — works with --requirepass
        decode_responses=True,
    )

    try:
        await redis.ping()
    except Exception as exc:
        print(f"ERROR: Cannot connect to Redis: {exc}")
        return

    print(f"Connected to Redis at {settings.redis_host}:{settings.redis_port}")
    print("\nStreams and Consumer Groups:")
    print("=" * 60)

    for stream in ALL_STREAMS:
        try:
            length = await redis.xlen(stream)
        except Exception:
            length = 0
        group = CONSUMER_GROUPS.get(stream, "N/A")
        print(f"  {stream:<40} len={length}  group={group}")

        try:
            await redis.xgroup_create(stream, group, id="0", mkstream=True)
            print(f"    ✓ Group '{group}' created/verified")
        except Exception as e:
            print(f"    ✓ Group already exists ({e})")

    print("\n" + "=" * 60)
    print("Stream setup complete!")

    print("\nCurrent stream stats:")
    for stream in ALL_STREAMS:
        try:
            length = await redis.xlen(stream)
            info = await redis.xinfo_stream(stream)
            first = await redis.xrange(stream, count=1)
            last = await redis.xrevrange(stream, count=1)
            print(f"  {stream}:")
            print(f"    Length: {length}")
            print(f"    First: {first[0][0] if first else 'empty'}")
            print(f"    Last: {last[0][0] if last else 'empty'}")
        except Exception as e:
            print(f"  {stream}: error={e}")

    await redis.close()


if __name__ == "__main__":
    asyncio.run(main())
