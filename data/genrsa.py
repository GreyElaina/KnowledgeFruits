import rsa

(pubkey, privkey) = rsa.newkeys(2048)

# 保存密钥
with open('public.pem','w+') as f:
    f.write(pubkey.save_pkcs1().decode())

with open('rsa.pem','w+') as f:
    f.write(privkey.save_pkcs1().decode())

