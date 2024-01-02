# redis 订阅端

import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)

def handle_message(message):
    print(f"Received message: {message['data'].decode()}")

pubsub = r.pubsub()
pubsub.subscribe('your_channel')

for message in pubsub.listen():
    if message['type'] == 'message':
        handle_message(message)

