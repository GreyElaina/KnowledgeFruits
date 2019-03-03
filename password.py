import hashlib
from base import CreateSalt

def crypt(password, salt=CreateSalt(length=8)):
    password += salt
    return hashlib.sha256(password.encode()).hexdigest()
    
if __name__ == '__main__':
    print(crypt("asd123456", CreateSalt(length=8)))