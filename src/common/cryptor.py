import random
import string
import hashlib

def saltgen(length=64):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def saltcat(raw, salt):
    return hashlib.sha512((salt + raw + salt).encode()).hexdigest()