import redis

redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True
)

def test_failed_login_counter():
    key = "test:failed_login"

    
    redis_client.delete(key)
    redis_client.set(key, 1)
    redis_client.incr(key)
    count = int(redis_client.get(key))
    assert count == 2

    redis_client.delete(key)