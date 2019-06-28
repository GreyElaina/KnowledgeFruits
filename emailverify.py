import zmail
from base import app, config
from flask import request, Response
import cacheout
import rsa
import base64
import re
import utils
import Exceptions

cache_verify = cacheout.Cache(ttl=0, maxsize=32768)
mailer = zmail.server(config.email.username, config.email.password)

class ConfigError(Exception):
    pass

if not (mailer.smtp_able() or mailer.pop_able()):
    raise ConfigError("your config of email is wrong.")

template_mail = {
    "subject": 'Knowledgefruits Register by email.',
    "content_text": """感谢你的注册, 现在, 你需要通过访问该URL来证明该邮箱属于你.
若你并没有在30分钟内在一KnowledgeFruits实例上进行过注册操作, 请忽略该条消息.

{REGISTER_URL}
"""
}

def decrypt(crypt_text):  # 用私钥解密
    privkey = rsa.PrivateKey.load_pkcs1(open('./data/rsa.pem').read().encode("utf-8"))
    lase_text = rsa.decrypt(base64.b64decode(crypt_text), privkey).decode("utf-8")  # 注意，这里如果结果是bytes类型，就需要进行decode()转化为str
    return lase_text

# 前端通知后端的方式:
# 当访问register页面时, 前端告知后端生成一registerId, 并存储于本地, 过期时间约为360s
# 按下注册按钮时, 将消息和registerId拼接, 后端存储消息, 并发送邮件.(前端这个时候还没设密码)
# 访问REGISTER_URL(前端会拼接一跳转URL), 然后跳转, 设置密码(前端使用yggdrasil那个密匙加密(base64下先)并发送到后端.)
@app.route("/api/email/verify", methods=['POST'])
def verify():
    data = request.json
    '''
    if decrypt(data.get("password")) == data.get("verify"):
        return Response(status=204)
    else:
        return Response(status=403)
    '''
    if not re.match(utils.StitchExpression(config.reMatch.UserEmail), data.get("email")):
        raise Exceptions.InvalidToken
