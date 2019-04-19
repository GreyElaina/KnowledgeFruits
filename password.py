import hashlib
from utils import CreateSalt
import rsa

def crypt(password, salt=CreateSalt(length=8)):
    password += salt
    return hashlib.sha256(password.encode()).hexdigest()

def decrypt(message, privatekey):
    filedata = open(privatekey).read()
    privatekey = rsa.PrivateKey.load_pkcs1(filedata.encode())
    return rsa.decrypt(message, privatekey).decode()
    
if __name__ == '__main__':
    print(crypt("asd123456", CreateSalt(length=8)))