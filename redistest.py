import redis

redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True
)

redis_client.set("failed:bestie@gmail.com", 1)
redis_client.incr("failed:bestie@gmail.com")
print(redis_client.get("failed:bestie@gmail.com"))





redis_client.set("failed:bestie@gmail.com", 4)
redis_client.incr("failed:bestie@gmail.com")
count = int(redis_client.get("failed:bestie@gmail.com"))
print(count)
if count >= 5:
    print("LOCK ACCOUNT 🚨")
    
    
for key in redis_client.keys("*"):
    print(f"{key} -> {redis_client.get(key)}")