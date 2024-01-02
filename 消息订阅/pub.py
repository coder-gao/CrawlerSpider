# redis 发布订阅

import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)
key_to_monitor = 'your_key'

# 在程序A中修改键值
new_value = 'new_value'
r.set(key_to_monitor, new_value)

# 发布消息到频道
r.publish('your_channel', f"{key_to_monitor}:{new_value}")
