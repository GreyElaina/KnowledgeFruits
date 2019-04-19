from base import config, cache, app, Token
from flask import request, Response
import json
import uuid
import model
import hashlib

@app.route("/api/knowledgefruits/serverinfo/knowledgefruits")
@app.route("/api/knowledgefruits/serverinfo")
@app.route("/api/knowledgefruits/")
def serverinfo():
    return Response(json.dumps({
        "Yggdrasil" : {
            "BaseUrl" : config.const.base
        },
        "OAuth": {
            "github": {
                "authorize_url": config.OAuth.github.authorize_url,
                "icon": config.OAuth.github.icon,
                "register": "".join([config.OAuth.github.authorize_url, "?", urlencode({
                    "client_id": config.OAuth.github.client_id,
                    "scope": config.OAuth.github.scope
                })])
            }
        },
        "TokenTime": raw_config['TokenTime']
    }), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/authenticate/security/signin", methods=['POST'])
def kf_randomkey_signin():
    if request.is_json:
        data = request.json
        Randomkey = password.CreateSalt(length=8)
        authid = data.get("authid")
        user_result = model.getuser(data['username'])
        if not user_result:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        salt = user_result.passwordsalt
        if user_result:
            IReturn = {
                "authId" : authid,
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt
            }
            cache.set(authid, {
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt,
                "VerifyValue" : user_result.password,
                "authId" : authid,
                "inorderto": "signin"
            }, ttl=30)
            return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)

@app.route("/api/knowledgefruits/authenticate/security/signout", methods=['POST'])
def kf_randomkey_signout():
    if request.is_json:
        data = request.json
        Randomkey = password.CreateSalt(length=8)
        authid = data.get("authid")
        user_result = model.getuser(data['username'])
        if not user_result:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        salt = user_result.passwordsalt
        if user_result:
            IReturn = {
                "authId" : authid,
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt
            }
            cache.set(authid, {
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt,
                "VerifyValue" : user_result.password,
                "authId" : authid,
                "inorderto": "signout"
            }, ttl=30)
            return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)

@app.route("/api/knowledgefruits/authenticate/security/verify", methods=['POST'])
def kf_login_verify():
    if request.is_json:
        data = request.json
        Data = cache.get(data.get("authId"))
        if not Data:
            return Response(status=403)
        else:
            user_result = model.getuser(Data['username'])
            if user_result:
                AuthRequest = password.crypt(user_result.password, Data['HashKey'])
                if AuthRequest == data['Password']:
                    if Data.get("inorderto") == "signin":
                        Token = model.token(accessToken=str(uuid.uuid4()).replace("-", ""), clientToken=str(uuid.uuid4()).replace("-", ""), bind=user_result.selected, email=user_result.email)
                        Token.save() # 颁发Token
                        IReturn = {
                            "accessToken" : Token.accessToken,
                            "clientToken" : Token.clientToken
                        }
                        cache_redis.delete(data['authId'])
                        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
                    if Data.get("inorderto") == "signout":
                        result = Token.getalltoken(user_result)
                        if result:
                            for i in result:
                                cache.delete(i)
                        return Response(status=204)
                else:
                    cache_redis.delete(data['authId'])
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Invalid credentials. Invalid username or password."
                    }
                    return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                cache_redis.delete(data['authId'])
                return Response(status=403)

@app.route("/api/knowledgefruits/authenticate/password/test", methods=['POST'])
def kf_passwd_test():
    if not re.match(base.StitchExpression(config.reMatch.UserPassword), request.data.decode()):
        return Response(status=400)
    else:
        return Response(status=204)

@app.route("/api/knowledgefruits/authenticate/email/test", methods=['POST'])
def kf_email_test():
    if not re.match(base.StitchExpression(config.reMatch.UserEmail), request.data.decode()):
        return Response(status=400)
    else:
        return Response(status=204)

@app.route("/api/knowledgefruits/authenticate/password/change/<username>", methods=['POST'])
def kf_user_changepasswd(username):
    if request.is_json:
        data = request.json
        user_result = model.getuser(username)
        if user_result:
            AccessToken = data['accessToken']
            ClientToken = data['clientToken'] if 'clientToken' in data else None
            if not ClientToken:
                token_result_boolean = model.is_validate(AccessToken)
                token = model.gettoken(AccessToken)
            else:
                token_result_boolean = model.is_validate(AccessToken, ClientToken)
                token = model.gettoken(AccessToken, ClientToken)
            if token_result_boolean and token:
                # 如果Token有效
                # 开始解析由公钥(/api/yggdrasil)加密的东西
                # 这玩意是个base64
                encrypt = base64.b64decode(data['Password'])
                decrypt_errorMessage = password.decrypt(encrypt, config.KeyPath.Private)
                user = model.getuser(token.email)
                if password.crypt(decrypt_errorMessage, user.passwordsalt) == user.password:
                    return Response(status=204)
                newsalt = base.CreateSalt(length=8)
                newpassword = password.crypt(decrypt_errorMessage, newsalt)
                user.password = newpassword
                user.passwordsalt = newsalt
                user.save()
                #开始否决所有的Token
                model.token.delete().where(model.token.email == user.email).execute()
                return Response(status=204)
            else:
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
        else:
            return Response(json.dumps({
                'error' : "ForbiddenOperationException",
                "errorMessage" : "Invalid token."
            }), status=403, mimetype="application/json; charset=utf-8")

@app.route("/api/knowledgefruits/search/textures/<path:args>")
def kf_texturesinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i] : args.split("/")[i + 1] for i in range(len(args.split("/")))[::2]}
    content = [model.textures.__dict__[i].field == Args[i] for i in Args.keys()][0]
    for i in [model.textures.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    try:
        return Response(json.dumps([
            model.kf_format_textures(i) for i in model.findtextures(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)

@app.route("/api/knowledgefruits/search/profiles/<path:args>")
def kf_profileinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i] : args.split("/")[i + 1] for i in range(len(args.split("/")))[::2]}
    content = [model.profile.__dict__[i].field == Args[i] for i in Args.keys()][0]
    for i in [model.profile.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    try:
        return Response(json.dumps([
            model.kf_format_profile(i) for i in model.findprofile(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)

@app.route("/api/knowledgefruits/search/id/user/<email>")
def kf_search_user_email(email):
    result = model.getuser(email)
    if not result:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "错误的参数"
        }), mimetype='application/json; charset=utf-8', status=403)
    return Response(json.dumps({"uuid": result.uuid}), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/authenticate/simple/refrush", methods=['GET', "POST"])
def kf_authenticate_simple_refrush():
    if request.is_json:
        data = request.json
        Can = False
        AccessToken = data.get('accessToken')
        ClientToken = data.get("clientToken", str(uuid.uuid4()).replace("-", ""))
        IReturn = {}
        if 'clientToken' in data:
            OldToken = Token.gettoken_strict(AccessToken, data.get("clientToken"))
        else:
            OldToken = Token.gettoken_strict(AccessToken)
        if not OldToken:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        
        if int(time.time()) >= OldToken.get("createTime") + (config.TokenTime.RefrushTime * config.TokenTime.TimeRange):
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        NewAccessToken = str(uuid.uuid4()).replace('-', '')
        cache.set(".".join(["token", NewAccessToken]), {
            "clientToken": OldToken.get('clientToken'),
            "bind": "",
            "user": OldToken.get("user"),
            "createTime": int(time.time())
        }, ttl=config.TokenTime.RefrushTime * config.TokenTime.TimeRange)
        cache.delete(".".join(["token", AccessToken]))
        IReturn['accessToken'] = NewAccessToken
        IReturn['clientToken'] = OldToken.get('clientToken')
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/simple/authserver/validate", methods=['POST'])
def kf_validate():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")
        result = Token.gettoken_strict(AccessToken, ClientToken)
        if not result:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        else:
            if Token.is_validate_strict(AccessToken, ClientToken):
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                return Response(status=204)

@app.route("/api/knowledgefruits/simple/authserver/invalidate", methods=['POST'])
def kf_invalidate():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")

        result = Token.gettoken(AccessToken, ClientToken)
        if result:
            cache.delete(".".join(['token', AccessToken]))
        else:
            if ClientToken:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        #User = model.user.get(email=result.email)
        '''if User.permission == 0:
            return Response(simplejson.dumps({
                'error' : "ForbiddenOperationException",
                'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
            }), status=403, mimetype='application/json; charset=utf-8')'''
        return Response(status=204)