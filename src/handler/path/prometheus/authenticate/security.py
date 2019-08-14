import uuid
import string
import random

# 该模块用于封装描述各个安全功能的底层.

def uniqueId():
    return uuid.uuid4()

def randomString(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))