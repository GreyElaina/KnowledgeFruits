import zmail
from base import app, config
from flask import request, Response
import cacheout
import rsa
import base64
import re
import utils
import Exceptions
import json
import model
import uuid
import password
from datetime import datetime

cache_verify = cacheout.Cache(ttl=0, maxsize=32768)
cache_limit = cacheout.Cache(ttl=0, maxsize=32768)
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
    try:
        privkey = rsa.PrivateKey.load_pkcs1(
            open('./data/rsa.pem').read().encode("utf-8"))
        lase_text = rsa.decrypt(base64.b64decode(crypt_text), privkey).decode(
            "utf-8") 
        return lase_text
    except rsa.pkcs1.DecryptionError:
        raise Exceptions.InvalidRequestData()  # 加密失误

@app.route("/api/knowledgefruits/register/", methods=['POST'])
def quest():
    data = request.json
    '''
    if decrypt(data.get("password")) == data.get("verify"):
        return Response(status=204)
    else:
        return Response(status=403)
    '''
    if not re.match(utils.StitchExpression(config.reMatch.UserEmail), data.get("email")):
        raise Exceptions.IllegalArgumentException()  # 邮箱不匹配
    if not re.match(utils.StitchExpression(config.reMatch.UserPassword), decrypt(data.get("password"))):
        raise Exceptions.InvalidToken()  # 密码不合格
    if not re.match(utils.StitchExpression(config.reMatch.PlayerName), data.get("username")):
        raise Exceptions.InvalidCredentials()  # 名称不合格
    if model.getuser(data.get("email")):
        raise Exceptions.DuplicateData()  # 已注册的用户

    if not cache_limit.get(data.get("email")):
        cache_limit.set(data.get("email"), "LIMITER", ttl=180)
    else:
        cache_limit.set(data.get("email"), "LIMITER", ttl=180)
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "Frequency limit, wait a moment."
        }), status=403, mimetype='application/json; charset=utf-8')

    password = decrypt(data.get("password"))
    salt = utils.CreateSalt(length=16)
    registerId = str(uuid.uuid4()).replace("-", "")

    cache_verify.set(registerId, {
        "email": data.get("email"),
        "password": {
            "context": password,
            "salt": salt
        },
        "username": data.get("username")
    }, ttl=60*30)
    mail = template_mail.copy()
    mail["content_text"] = mail["content_text"].format(REGISTER_URL=("".join(
        [config.HostUrl, "/api/knowledgefruits/register/verify?registerId=", registerId])))
    mailer.send_mail(data.get("email"), mail)

    return Response(status=204)


@app.route('/api/knowledgefruits/register/verify')
def verify():
    data = cache_verify.get(request.args.get("registerId"))
    if not data:
        raise Exceptions.InvalidToken()
    if model.getuser(data.get("email")):
        raise Exceptions.InvalidToken()
    result = model.user(username=data.get("username"), email=data.get("email"), 
        password=password.crypt(data["password"]['context'], data["password"]['salt']),
        passwordsalt=data["password"]['salt'],
        register_time=datetime.now(),
        last_login=0,
        last_joinserver=0
    )
    result.save()
    cache_verify.delete(request.args.get("registerId"))
    return Response(status=204)