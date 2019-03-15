import rsa
import base64

# 生成密钥
#(pubkey, privkey) = rsa.newkeys(1024)

'''
# 保存密钥
with open('public.pem','w+') as f:
    f.write(pubkey.save_pkcs1().decode())

with open('private.pem','w+') as f:
    f.write(privkey.save_pkcs1().decode())
'''

# 导入密钥
with open('../data/public.pem','r') as f:
    pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())

with open('../data/rsa.pem','r') as f:
    privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())

# 明文
message = 'Sdl930402'

# 公钥加密
crypto = rsa.encrypt(message.encode(), pubkey)
print(type(crypto))
print(base64.b64encode(crypto))

# 私钥解密
message = rsa.decrypt(crypto, privkey).decode()
print(type(message))


# 私钥签名
signature = rsa.sign(message.encode(), privkey, 'SHA-1')

# 公钥验证
rsa.verify(message.encode(), signature, pubkey)