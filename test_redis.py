import pytest
import os
import redis

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True
)

@pytest.mark.skip(reason="Redis integration test skipped in CI")
def test_failed_login_counter():
    key = "test:failed_login"

    redis_client.delete(key)
    redis_client.set(key, 1)
    redis_client.incr(key)

    val = redis_client.get(key)
    count = int(val) if val is not None else 0

    assert count == 2

    redis_client.delete(key)