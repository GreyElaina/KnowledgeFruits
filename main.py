import base64
import datetime
import json
import os
import re
import time
import uuid
from datetime import timedelta
from os.path import exists as FileExists
from urllib.parse import parse_qs, urlencode, urlparse

import peewee
import requests
from flask import (Flask, Response, abort, redirect, render_template, request,
                   session, url_for)
from flask.helpers import make_response
from werkzeug.contrib.fixers import LighttpdCGIRootFix
from werkzeug.exceptions import HTTPException
import cacheout

import base
import model
import password
import searchcache

config = base.Dict2Object(json.loads(open("./data/config.json").read()))
raw_config = json.loads(open("./data/config.json").read())

app = Flask(__name__)
app.config['SECRET_KEY'] = config.salt
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=1)
#app.config['UPLOAD_FOLDER'] = os.getcwd() + "/data/texture/"

cache = cacheout.Cache(ttl=0)
Token = searchcache.TokenCache(cache)
class FlaskConfig(object):
    SCHEDULER_API_ENABLED = True

app.config.from_object(FlaskConfig())

@app.errorhandler(429)
def ratelimit_handler(e):
    return Response(status=403)
'''
@app.errorhandler(404)
def notfound(e):
    return redirect(url_for('service_error', error="没有找到数据", errorMessage="请检查url是否正确.", status=404))
'''

@app.route("/api/knowledgefruits/serverinfo/yggdrasil")
@app.route(config.const.base + '/', methods=['GET'])
def index():
    return Response(json.dumps({
        "meta" : config.YggdrasilIndexData,
        "skinDomains": config.SiteDomain if "SiteDomain" in config.__dict__ else [urlparse(request.url).netloc.split(":")[0]],
        "signaturePublickey": open(config.KeyPath.Public, 'r').read()
    }), mimetype='application/json; charset=utf-8')

# /authserver
@app.route(config.const.base + '/authserver/authenticate', methods=['POST'])
def authenticate():
    IReturn = {}
    if request.is_json:
        data = request.json
        user = model.getuser(data['username'])
        if not user:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        '''if user.permission == 0:
            return Response(json.dumps({
                'error' : "ForbiddenOperationException",
                'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
            }), status=403, mimetype='application/json; charset=utf-8')'''
        if not cache.get(".".join(['lock', user.email])):
            cache.set(".".join(['lock', user.email]), "LOCKED", ttl=config.AuthLimit)
        else:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')

        SelectedProfile = {}
        AvailableProfiles = []
        if password.crypt(data['password'], user.passwordsalt) == user.password:
            # 登录成功.
            ClientToken = data['clientToken'] if "clientToken" in data else str(uuid.uuid4()).replace("-","")
            AccessToken = str(uuid.uuid4()).replace("-","")
            notDoubleProfile = False

            try:
                AvailableProfiles = [
                    model.format_profile(i, unsigned=True) for i in model.profile.select().where(model.profile.createby==user.uuid)
                ]
            except Exception as e:
                if "profileDoesNotExist" == e.__class__.__name__:
                    pass

            Profileresult = model.getprofile_createby(user.uuid)
            if len(Profileresult) == 1:
                notDoubleProfile = True
                SelectedProfile = model.format_profile(Profileresult.get())

            cache.set(".".join(["token", AccessToken]), {
                "clientToken": ClientToken,
                "bind": Profileresult.get().uuid if notDoubleProfile else None,
                "user": user.uuid,
                "createTime": int(time.time())
            }, ttl=config.TokenTime.RefrushTime)

            IReturn = {
                "accessToken" : AccessToken,
                "clientToken" : ClientToken,
                "availableProfiles" : AvailableProfiles,
                "selectedProfile" : SelectedProfile
            }
            if "requestUser" in data:
                if data['requestUser']:
                    IReturn['user'] = model.format_user(user)

            if IReturn['selectedProfile'] == {}:
                del IReturn['selectedProfile']
        else:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const.base + '/authserver/refresh', methods=['POST'])
def refresh():
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
        
        if int(time.time()) >= OldToken.get("createTime") + config.TokenTime.RefrushTime:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        User = model.getuser_uuid(OldToken.get("user"))
        TokenSelected = OldToken.get("bind")
        if TokenSelected:
            TokenProfile = model.getprofile_uuid(TokenSelected).get()
        else:
            TokenProfile = {}
        if 'selectedProfile' in data:
            PostProfile = data['selectedProfile']
            needuser = model.getprofile_id_name(PostProfile['id'], PostProfile['name'])
            if not needuser: # 验证客户端提供的角色信息
                error = {
                    'error' : "IllegalArgumentException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=400, mimetype='application/json; charset=utf-8')
                # 角色不存在.
            else:
                needuser = needuser.get()
                # 验证完毕,有该角色.
                if OldToken.get('bind'): # 如果令牌本来就绑定了角色
                    error = {
                        'error' : 'IllegalArgumentException',
                        'errorMessage' : "Access token already has a profile assigned."
                    }
                    return Response(json.dumps(error), status=400, mimetype='application/json; charset=utf-8')
                if needuser.createby != OldToken.get("user"): # 如果角色不属于用户
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Attempting to bind a token to a role that does not belong to its corresponding user."
                    }
                    return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                TokenSelected = model.findprofilebyid(PostProfile['id']).uuid
                IReturn['selectedProfile'] = model.format_profile(model.findprofilebyid(PostProfile['id']), unsigned=True)
                Can = True

        NewAccessToken = str(uuid.uuid4()).replace('-', '')
        cache.set(".".join(["token", NewAccessToken]), {
            "clientToken": OldToken.get('clientToken'),
            "bind": TokenSelected,
            "user": OldToken.get("user"),
            "createTime": int(time.time())
        }, ttl=config.TokenTime.RefrushTime)

        cache.delete(".".join(["token", AccessToken]))
        IReturn['accessToken'] = NewAccessToken
        IReturn['clientToken'] = OldToken.get('clientToken')
        if TokenProfile and not Can:
            IReturn['selectedProfile'] = model.format_profile(TokenProfile, unsigned=True)
        if 'requestUser' in data:
            if data['requestUser']:
                IReturn['user'] = model.format_user(User)
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')


#查看令牌状态
@app.route(config.const.base + "/authserver/validate", methods=['POST'])
def validate():
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

@app.route(config.const.base + "/authserver/invalidate", methods=['POST'])
def invalidate():
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

#@limit
@app.route(config.const.base + '/authserver/signout', methods=['POST'])
def signout():
    if request.is_json:
        data = request.json
        email = data['username']
        passwd = data['password']
        result = model.getuser(email)
        if not result:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        else:
            '''if result.permission == 0:
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }), status=403, mimetype='application/json; charset=utf-8')'''
            if not cache.get(".".join(['lock', result.email])):
                cache.set(".".join(['lock', result.email]), "LOCKED", ttl=config.AuthLimit)
            else:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            if password.crypt(passwd, salt=result.passwordsalt) == result.password:
                result = Token.getalltoken(result)
                if result:
                    for i in result:
                        cache.delete(i)
                return Response(status=204)
            else:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')

# /authserver

################

# /sessionserver
@app.route(config.const.base + "/sessionserver/session/minecraft/join", methods=['POST'])
def joinserver():
    token = {}
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")
        TokenValidate = Token.is_validate_strict(AccessToken, ClientToken)
        
        if not TokenValidate:
            # Token有效
            # uuid = token.bind
            token = Token.gettoken_strict(AccessToken, ClientToken)
            if not token:
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
            if token.get('bind'):
                result = model.getprofile_uuid(token.get('bind'))
                if not result:
                    return Response(status=404)
            else:
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
            player = model.getprofile(result.get().name).get()
            playeruuid = player.profile_id.replace("-", "")
            if data['selectedProfile'] == playeruuid:
                cache.set(data['serverId'], {
                    "accessToken": AccessToken,
                    "selectedProfile": data['selectedProfile'],
                    "remoteIP": request.remote_addr
                }, ttl=config.ServerIDOutTime)
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

@app.route(config.const.base + "/sessionserver/session/minecraft/hasJoined", methods=['GET'])
def PlayerHasJoined():
    args = request.args
    ServerID = args['serverId']
    PlayerName = args['username']
    RemoteIP = args['ip'] if 'ip' in args else None
    Successful = False
    Data = cache.get(ServerID)
    if not Data:
        return Response(status=204)
    TokenInfo = Token.gettoken(Data['accessToken'])
    ProfileInfo = model.getprofile_uuid_name(TokenInfo.get("bind"), name=PlayerName)
    if not TokenInfo or not ProfileInfo:
        return Response(status=204)

    ProfileInfo = ProfileInfo.get()

    Successful = PlayerName == ProfileInfo.name and [True, RemoteIP == Data['remoteIP']][bool(RemoteIP)]
    if Successful:
        result = json.dumps(model.format_profile(
            ProfileInfo,
            Properties=True,
            unsigned=False,
            BetterData=True
        ))
        return Response(result, mimetype="application/json; charset=utf-8")
    else:
        return Response(status=204)
    return Response(status=204)

@app.route(config.const.base + '/sessionserver/session/minecraft/profile/<getuuid>', methods=['GET'])
def searchprofile(getuuid):
    args = request.args
    result = model.getprofile_id(getuuid)
    if not result:
        return Response(status=204)
    else:
        result = result.get()
    IReturn = model.format_profile(
        #model.user.get(model.user.playername == model.profile.get(profile_id=getuuid).name),
        result,
        Properties=True,
        unsigned={"false": False, "true": True, None: True}[args.get('unsigned')],
        BetterData=True
    )
    return Response(response=json.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const.base + '/api/profiles/minecraft', methods=['POST'])
def searchmanyprofile():
    if request.is_json:
        data = list(set(list(request.json)))
        IReturn = []
        for i in range(config.ProfileSearch.MaxAmount - 1):
            try:
                IReturn.append(model.format_profile(model.profile.get(model.profile.name==data[i]), unsigned=True))
            except model.profile.DoesNotExist:
                continue
            except IndexError:
                pass
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
    return Response(status=404)

# /sessionserver

#####################

# /api/knowledgefruits/
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

@app.route("/api/knowledgefruits/authenticate/security", methods=['POST'])
def kf_randomkey():
    if request.is_json:
        data = request.json
        Randomkey = password.CreateSalt(length=8)
        authid = data['authid'] if 'authid' in data else str(uuid.uuid4()).replace('-', '')
        try:
            user_result = model.getuser(data['username'])
        except Exception as e:
            if "userDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
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
            cache_redis.hmset(authid, {
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt,
                "VerifyValue" : user_result.password,
                "authId" : authid
            })
            cache_redis.expire(authid, 30)
            return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)

@app.route("/api/knowledgefruits/authenticate/security/verify", methods=['POST'])
def kf_login_verify():
    if request.is_json:
        data = request.json
        Data = cache_redis.hgetall(data['authId'])
        Data = {i.decode(): Data[i].decode() for i in Data.keys()}
        if not Data:
            return Response(status=403)
        else:
            user_result = model.getuser(Data['username'])
            if user_result:
                AuthRequest = password.crypt(user_result.password, Data['HashKey'])
                if AuthRequest == data['Password']:
                    Token = model.token(accessToken=str(uuid.uuid4()).replace("-", ""), clientToken=str(uuid.uuid4()).replace("-", ""), bind=user_result.selected, email=user_result.email)
                    Token.save() # 颁发Token
                    IReturn = {
                        "accessToken" : Token.accessToken,
                        "clientToken" : Token.clientToken
                    }
                    cache_redis.delete(data['authId'])
                    return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
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
        AccessToken = data['accessToken']
        ClientToken = data['clientToken'] if 'clientToken' in data else str(uuid.uuid4()).replace("-", "")
        try:
            if 'clientToken' in data:
                OldToken = model.token.get(accessToken=AccessToken, clientToken=ClientToken)
            else:
                OldToken = model.token.get(accessToken=AccessToken)
        except Exception as e:
            if "tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e

        if OldToken.status not in ["0", "1"]:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        User = model.user.get(uuid=OldToken.user)

        NewToken = model.token(accessToken=str(uuid.uuid4()).replace('-', ''), clientToken=OldToken.clientToken, user=OldToken.user, bind=TokenSelected)
        NewToken.save()
        OldToken.delete_instance()
        IReturn = {
            "accessToken" : NewToken.accessToken,
            'clientToken' : OldToken.clientToken,
            #'selectedProfile' : {}
        }
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/simple/authserver/validate", methods=['POST'])
def kf_validate():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data['clientToken'] if "clientToken" in data else None
        try:
            if not ClientToken:
                result = model.token.get(model.token.accessToken == AccessToken)
            else:
                result = model.token.get(model.token.accessToken == AccessToken, model.token.clientToken == ClientToken)
        except Exception as e:
            if "tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            #User = model.user.get(email=result.email)
            '''if User.permission == 0:
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
                }), status=403, mimetype='application/json; charset=utf-8')'''

            if result.status in ["2", "1"]:
                if result.status == "2":
                    result.delete_instance()
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
        ClientToken = data['clientToken'] if "clientToken" in data else None
        try:
            if ClientToken == None:
                try:
                    result = model.token.get(model.token.accessToken == AccessToken)
                except Exception as e:
                    if "tokenDoesNotExist" == e.__class__.__name__:
                        return Response(status=204)
            else:
                try:
                    result = model.token.get(model.token.accessToken == AccessToken & model.token.clientToken == ClientToken)
                except Exception as e:
                    if "tokenDoesNotExist" == e.__class__.__name__:
                        result = model.token.get(model.token.accessToken == AccessToken)
        except Exception as e:
            if "tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            result.delete_instance()
            return Response(status=204)

#@limit
@app.route('/api/knowledgefruits/authenticate/security/signout/verify', methods=['POST'])
def kf_signout():
    if request.is_json:
        data = request.json
        Data = cache_redis.hgetall(data['authId'])
        Data = {i.decode(): Data[i].decode() for i in Data.keys()}
        if cache_redis.get(".".join(['lock', user_result.email])):
            return Response(status=403)
        if not Data:
            return Response(status=403)
        else:
            user_result = model.getuser(Data['username'])
            if user_result:
                if not cache_redis.get(".".join(['lock', user_result.email])):
                    cache_redis.setnx(".".join(['lock', user_result.email]), "locked")
                    cache_redis.expire(".".join(['lock', user_result.email]), config.AuthLimit)
                else:
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Invalid credentials. Invalid username or password."
                    }
                    return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                AuthRequest = password.crypt(user_result.password, Data['HashKey'])
                if AuthRequest == data['Password']:
                    model.token.delete().where(model.token.user == user_result.uuid).execute()
                else:
                    cache_redis.delete(data['authId'])
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Invalid credentials. Invalid username or password."
                    }
                    return Response(json.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                cache_redis.delete(data['authId'])
                return Response(json.dumps({
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }), status=403)

#####################
@app.route("/texture/<image>", methods=['GET'])
def imageview(image):
    try:
        with open(os.getcwd() + "/data/texture/" + image + '.png', "rb") as f:
            image = f.read()
    except FileNotFoundError:
        return Response(status=404)
    return Response(image, mimetype='image/png')

@app.route("/texture/<image>/head", methods=['GET'])
def imageview_head(image):
    try:
        filename = "".join([os.getcwd(), "/data/texture/", image, '.png'])
        texture = model.gettexture_hash(base.PngBinHash(filename))
        if not texture:
            return redirect(url_for('service_error',
                error="Not Found",
                errorMessage="无法找到相应文件.",
                status=404)
            )
        if texture.type != "SKIN":
            return Response(json.dumps(dict(
                error="皮肤请求类型错误",
                errorMessage="无法抓取该类型皮肤文件的head部分",
            )), status=403)
        image = base.gethead_skin(filename)
    except FileNotFoundError:
        return Response(status=404)
    return Response(image, mimetype='image/png')

if __name__ == '__main__':
    if FileExists('./data/global.db'):
        model.db['global'].create_tables([model.profile, model.token, model.user, model.textures])
    if False in [FileExists(config.KeyPath.Private), FileExists(config.KeyPath.Public)]:
        import rsa
        (public, private) = rsa.newkeys(2048)
        with open(config.KeyPath.Private, 'wb') as f:
            f.write(private.save_pkcs1())
        with open(config.KeyPath.Public, 'wb') as f:
            f.write(public.save_pkcs1())
    app.wsgi_app = LighttpdCGIRootFix(app.wsgi_app)
    from paste.translogger import TransLogger
    import waitress
    import paste
    waitress.serve(TransLogger(app, setup_console_handler=False), host='0.0.0.0', port=5001)