import base64
import datetime
import os
import re
import time
import uuid
from datetime import timedelta
from os.path import exists as FileExists
from urllib.parse import parse_qs, urlencode, urlparse

import peewee
import redis
import requests
import simplejson
from flask import (Flask, Response, abort, redirect, render_template, request,
                   session, url_for)
from flask.helpers import make_response
from flask_apscheduler import APScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.contrib.fixers import LighttpdCGIRootFix
from werkzeug.exceptions import HTTPException, NotFound

import base
import model
import password

config = base.Dict2Object(simplejson.loads(open("./data/config.json").read()))
raw_config = simplejson.loads(open("./data/config.json").read())

app = Flask(__name__)
app.config['SECRET_KEY'] = config.salt
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=1)
#app.config['UPLOAD_FOLDER'] = os.getcwd() + "/data/texture/"
cache_redis = redis.Redis(**raw_config['redis'])

class FlaskConfig(object):
    JOBS = [
        {
            'id': 'ChangeStatus',
            'func': 'main:CheckTokenStatus',
            'args': (),
            'trigger': 'interval',
            'minutes' : config.ScavengerSetting.CheckStatus
        },
        {
            'id': 'ClearDisabledTokens',
            'func': 'main:DeleteDisabledToken',
            'args': (),
            'trigger': 'interval',
            'minutes' : config.ScavengerSetting.DeleteDisabled
        },
    ]

    SCHEDULER_API_ENABLED = True

def OutTime(token):
    '''
    token.status = \
        1 if not config.TokenOutTime['canUse'](time.time() - time.mktime(token.setuptime.timetuple())) else\
        2 if not config.TokenOutTime['NeedF5'](time.time() - time.mktime(token.setuptime.timetuple())) else\
        0
    '''
    Enable = lambda time: time <= (config.TokenTime.TimeRange * config.TokenTime.EnableTime)
    Refrush = lambda time: time <= (config.TokenTime.TimeRange * config.TokenTime.RefrushTime) and time >= (config.TokenTime.TimeRange * config.TokenTime.EnableTime)
    if Enable(time.time() - time.mktime(token.setuptime.timetuple())):
        token.status = 0
    elif Refrush(time.time() - time.mktime(token.setuptime.timetuple())):
        token.status = 1
    else:
        token.status = 2
    token.save()
    # 0:可以进行操作
    # 1:只能刷新
    # 2:已经失效,无法执行任何操作

def CheckTokenStatus():
    for i in model.token.select().where(model.token.status == 0 | model.token.status == 1):
        OutTime(i)

def DeleteDisabledToken():
    # 删除失效Token(token.status == 2)
    model.token.delete().where(model.token.status == 2).execute()

app.config.from_object(FlaskConfig())
crontab = APScheduler()
crontab.init_app(app)
crontab.start()
cache = {
    'Login_randomkeys' : {}
}

@app.errorhandler(429)
def ratelimit_handler(e):
    return Response(status=403)

@app.errorhandler(404)
def notfound(e):
    return redirect(url_for('service_error', error="没有找到数据", errorMessage="请检查url是否正确.", status=404))

@app.route(config.const.base + '/', methods=['GET'])
def index():
    return Response(simplejson.dumps({
        "meta" : config.YggdrasilIndexData,
        "skinDomains": config.SiteDomain if "SiteDomain" in config.__dict__ else [urlparse(request.url).netloc.split(":")[0]],
        "signaturePublickey": open(config.KeyPath.Public, 'r').read()
    }), mimetype='application/json; charset=utf-8')

# /authserver

#@limiter.exempt
#@limiter.limit("1/second", error_message=Response(status=403))
@app.route(config.const.base + '/authserver/authenticate', methods=['POST'])
def authenticate():
    IReturn = {}
    if request.is_json:
        data = request.json
        user = {}
        try:
            user = model.user.get(model.user.email==data['username'])
        except Exception as e:
            if "userDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        '''if user.permission == 0:
            return Response(simplejson.dumps({
                'error' : "ForbiddenOperationException",
                'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
            }), status=403, mimetype='application/json; charset=utf-8')'''
        if not cache_redis.get(".".join(['lock', user.email])):
            cache_redis.setnx(".".join(['lock', user.email]), "locked")
            cache_redis.expire(".".join(['lock', user.email]), config.AuthLimit)
        else:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')

        SelectedProfile = {}
        AvailableProfiles = []
        if password.crypt(data['password'], user.passwordsalt) == user.password:
            # 登录成功.
            ClientToken = data['clientToken'] if "clientToken" in data else str(uuid.uuid4()).replace("-","")
            AccessToken = str(uuid.uuid4()).replace("-","")
            notDoubleProfile = False

            try:
                AvailableProfiles = [
                    model.format_profile(i, unsigned=True) for i in model.profile.select().where(model.profile.createby==user.email)
                ]
            except Exception as e:
                if "profileDoesNotExist" == e.__class__.__name__:
                    AvailableProfiles = []

            try:
                #print(model.profile.get(uuid=user.selected).name)
                Profileresult = model.profile.select().where(model.profile.createby == user.email)
                if len(Profileresult) != 1:
                    SelectedProfile = model.format_profile(model.profile.get(uuid=user.selected), unsigned=True)
                else:
                    notDoubleProfile = True
                    SelectedProfile = model.format_profile(Profileresult.get())
            except Exception as e:
                if "profileDoesNotExist" == e.__class__.__name__:
                    SelectedProfile = {}

            if notDoubleProfile:
                Token = model.token(accessToken=AccessToken, clientToken=ClientToken, bind=Profileresult.get().uuid, email=user.email)
            else:
                Token = model.token(accessToken=AccessToken, clientToken=ClientToken, email=user.email)
            Token.save() # 颁发Token

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
            return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const.base + '/authserver/refresh', methods=['POST'])
def refresh():
    if request.is_json:
        data = request.json
        Can = False
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
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e

        if OldToken.status not in ["0", "1"]:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid token."
            }
            return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
        User = model.user.get(email=OldToken.email)
        '''if User.permission == 0:
            return Response(simplejson.dumps({
                'error' : "ForbiddenOperationException",
                'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
            }), status=403, mimetype='application/json; charset=utf-8')'''
        TokenSelected = OldToken.bind
        if TokenSelected:
            TokenProfile = model.profile.get(uuid=TokenSelected)
        else:
            TokenProfile = {}
        if 'selectedProfile' in data:
            PostProfile = data['selectedProfile']
            # 验证客户端提供的角色信息
            try:
                needuser = model.profile.get(profile_id=PostProfile['id'], name=PostProfile['name'])
            except Exception as e:
                if "profileDoesNotExist" == e.__class__.__name__:
                    error = {
                        'error' : "IllegalArgumentException",
                        'errorMessage' : "Invalid token."
                    }
                    return Response(simplejson.dumps(error), status=400, mimetype='application/json; charset=utf-8')
                    # 角色不存在.yggdrasil文档没有明确规定,故不填
                #raise e
            else:
                # 验证完毕,有该角色.
                # 试图向一个已经绑定了角色的令牌指定其要绑定的角色
                if TokenSelected:
                    error = {
                        'error' : 'IllegalArgumentException',
                        'errorMessage' : "Access token already has a profile assigned."
                    }
                    return Response(simplejson.dumps(error), status=400, mimetype='application/json; charset=utf-8')
                if OldToken.bind:
                    error = {
                        'error' : 'IllegalArgumentException',
                        'errorMessage' : "Access token already has a profile assigned."
                    }
                    return Response(simplejson.dumps(error), status=400, mimetype='application/json; charset=utf-8')
                if needuser.createby != OldToken.email:
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Attempting to bind a token to a role that does not belong to its corresponding user."
                    }
                    return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                TokenSelected = model.findprofilebyid(PostProfile['id']).uuid
                Can = True

        NewToken = model.token(accessToken=str(uuid.uuid4()).replace('-', ''), clientToken=OldToken.clientToken, email=OldToken.email, bind=TokenSelected)
        NewToken.save()
        OldToken.delete_instance()
        IReturn = {
            "accessToken" : NewToken.accessToken,
            'clientToken' : OldToken.clientToken,
            #'selectedProfile' : {}
        }
        if TokenProfile:
            IReturn['selectedProfile'] = model.format_profile(TokenProfile, unsigned=True)
        if Can:
            IReturn['selectedProfile'] = model.format_profile(model.findprofilebyid(PostProfile['id']), unsigned=True)
        if 'requestUser' in data:
            if data['requestUser']:
                IReturn['user'] = model.format_user(User)
        return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const.base + "/authserver/validate", methods=['POST'])
def validate():
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
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            #User = model.user.get(email=result.email)
            '''if User.permission == 0:
                return Response(simplejson.dumps({
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
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                return Response(status=204)

@app.route(config.const.base + "/authserver/invalidate", methods=['POST'])
def invalidate():
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
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                #return Response(status=204)
            raise e
        else:
            #User = model.user.get(email=result.email)
            '''if User.permission == 0:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
                }), status=403, mimetype='application/json; charset=utf-8')'''
            result.delete_instance()
            return Response(status=204)

#@limit
@app.route(config.const.base + '/authserver/signout', methods=['POST'])
def signout():
    if request.is_json:
        data = request.json
        email = data['username']
        passwd = data['password']
        try:
            result = model.user.get(model.user.email == email)
        except Exception as e:
            if "userDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            '''if result.permission == 0:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }), status=403, mimetype='application/json; charset=utf-8')'''
            if not cache_redis.get(".".join(['lock', result.email])):
                cache_redis.setnx(".".join(['lock', result.email]), "locked")
                cache_redis.expire(".".join(['lock', result.email]), config.AuthLimit)
            else:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            if password.crypt(passwd, salt=result.passwordsalt) == result.password:
                try:
                    model.token.delete().where(model.token.email == result.email).execute()
                except Exception as e:
                    if "userDoesNotExist" == e.__class__.__name__:
                        error = {
                            'error' : "ForbiddenOperationException",
                            'errorMessage' : "Invalid credentials. Invalid username or password."
                        }
                        return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                    raise e
                else:
                    return Response(status=204)
            else:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')

# /authserver

################

# /sessionserver
@app.route(config.const.base + "/sessionserver/session/minecraft/join", methods=['POST'])
def joinserver():
    token = {}
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data['clientToken'] if "clientToken" in data else None

        TokenValidate = model.is_validate(AccessToken, ClientToken)
        
        if TokenValidate:
            # Token有效
            # uuid = token.bind
            token = model.gettoken(AccessToken, ClientToken)
            if token.bind:
                try:
                    result = model.profile.get(uuid=token.bind)
                except Exception as e:
                    if "profileDoesNotExist" == e.__class__.__name__:
                        return Response(status=404)
                    raise e
            else:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
            playeruuid = model.profile.get(name=result.name).profile_id.replace("-", "")
            if data['selectedProfile'] == playeruuid:
                #sj = model.ms_serverjoin(
                #    AccessToken=AccessToken,
                #    SelectedProfile=data['selectedProfile'],
                #    ServerID=data['serverId'],
                #    RemoteIP=request.remote_addr
                #)
                #sj.save()
                cache_redis.hmset(data['serverId'], {
                    "accessToken": AccessToken,
                    "selectedProfile": data['selectedProfile'],
                    "remoteIP": request.remote_addr
                })
                cache_redis.expire(data['serverId'], config.ServerIDOutTime)
                return Response(status=204)
            else:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
        else:
            return Response(simplejson.dumps({
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
    Data = cache_redis.hgetall(ServerID)
    Data = {i.decode(): Data[i].decode() for i in Data.keys()}
    if not Data:
        return Response(status=204)
    try:
        TokenInfo = model.token.get(accessToken=Data['accessToken'])
        ProfileInfo = model.profile.get(uuid=TokenInfo.bind, name=PlayerName)
    except Exception as e:
        if "DoesNotExist" in e.__class__.__name__:
            return Response(status=204)
        raise e

    Successful = PlayerName == ProfileInfo.name and [True, RemoteIP == Data['remoteIP']][bool(RemoteIP)]
    if Successful:
        result = simplejson.dumps(model.format_profile(
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
    signed = False
    IReturn = {}
    if 'unsigned' in args:
        signed = True if args['unsigned'] == 'true' else False
        #signed = False if args['unsigned'] == 'false' else True
        if args['unsigned'] == 'false':
            try:
                result = model.profile.get(profile_id=getuuid)
                IReturn = model.format_profile(
                    #model.user.get(model.user.playername == model.profile.get(profile_id=getuuid).name),
                    result,
                    Properties=True,
                    unsigned=False,
                    unMetaData=[True, False][model.getskintype_profile(result) == "SKIN" and model.getskinmodel_profile(result) == "ALEX"]
                )
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    return Response(status=204)
                raise e
            return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
        if args['unsigned'] == 'true':
            try:
                result = model.profile.get(profile_id=getuuid)
                IReturn = model.format_profile(
                    #model.user.get(model.user.playername == model.profile.get(profile_id=getuuid).name),
                    result,
                    Properties=True,
                    unsigned=True,
                    unMetaData=[True, False][model.getskintype_profile(result) == "SKIN" and model.getskinmodel_profile(result) == "ALEX"]
                )
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    return Response(status=204)
                raise e
            return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
    else:
        try:
            result = model.profile.get(profile_id=getuuid)
            IReturn = model.format_profile(
                #model.user.get(model.user.playername == model.profile.get(profile_id=getuuid).name),
                result,
                Properties=True,
                unsigned=True,
                unMetaData=[True, False][model.getskintype_profile(result) == "SKIN" and model.getskinmodel_profile(result) == "ALEX"]
            )
        except Exception as e:
            if "DoesNotExist" in e.__class__.__name__:
                return Response(status=204)
            raise e
        return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const.base + '/api/profiles/minecraft', methods=['POST'])
def searchmanyprofile():
    if request.is_json:
        data = list(set(list(request.json)))
        IReturn = list()
        for i in range(config.ProfileSearch.MaxAmount - 1):
            try:
                IReturn.append(model.format_profile(model.profile.select().where(model.profile.name==data[i]).get(), unsigned=True))
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    continue
        return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
    return Response(status=404)

# /sessionserver

#####################

# /api/knowledgefruits/
@app.route("/api/knowledgefruits/", methods=['GET', 'POST'])
def serverinfo():
    return Response(simplejson.dumps({
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

@app.route("/api/knowledgefruits/login/randomkey", methods=['POST'])
def kf_login_randomkey():
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
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        if not user_result:
            error = {
                'error' : "ForbiddenOperationException",
                'errorMessage' : "Invalid credentials. Invalid username or password."
            }
            return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
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
            return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)

@app.route("/api/knowledgefruits/login/randomkey/verify", methods=['POST'])
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
                    return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
                else:
                    cache_redis.delete(data['authId'])
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Invalid credentials. Invalid username or password."
                    }
                    return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                cache_redis.delete(data['authId'])
                return Response(status=403)
            
@app.route("/api/knowledgefruits/user/changepassword/<username>", methods=['POST'])
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
                decrypt_message = password.decrypt(encrypt, config.KeyPath.Private)
                user = model.getuser(token.email)
                if password.crypt(decrypt_message, user.passwordsalt) == user.password:
                    return Response(status=204)
                newsalt = base.CreateSalt(length=8)
                newpassword = password.crypt(decrypt_message, newsalt)
                user.password = newpassword
                user.passwordsalt = newsalt
                user.save()
                #开始否决所有的Token
                model.token.delete().where(model.token.email == user.email).execute()
                return Response(status=204)
            else:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
        else:
            return Response(simplejson.dumps({
                'error' : "ForbiddenOperationException",
                "errorMessage" : "Invalid token."
            }), status=403, mimetype="application/json; charset=utf-8")

@app.route("/api/knowledgefruits/oauth/github/resource")
def github_resource():
    code = request.args.get("code")
    if not code:
        error = {
            'error' : "ForbiddenOperationException",
            'errorMessage' : "Invalid credentials. Invalid username or password."
        }
        return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
    Data = simplejson.loads(cache_redis.get(".".join(["OAuth", "github", "response", code])))
    if not Data:
        return Response(status=404)
    return Response(simplejson.dumps(Data), mimetype='application/json; charset=utf-8')

@app.route('/api/knowledgefruits/oauth/github/callback')
def authorized():
    code = request.args.get("code")
    if not code:
        error = {
            'error' : "ForbiddenOperationException",
            'errorMessage' : "Invalid credentials. Invalid username or password."
        }
        return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
 
    r = requests.get(config.OAuth.github.access_token_url, params={
        "client_id": config.OAuth.github.client_id,
        "client_secret": config.OAuth.github.client_secret,
        "code": code,
        "redirect_uri": "http://127.0.0.1:5001/api/knowledgefruits/oauth/github/callback"
    }).text
    data = parse_qs(r)
    accessToken = data['access_token'][0]
    r = requests.get(config.OAuth.github.user, params={
        "access_token": accessToken
    }).json()
    face = r.get("avatar_url", "")
    if r.get("email") != None:
        email = r.get("email")
    else:
        result = requests.get(config.OAuth.github.email, params={
            "access_token": accessToken,
            "scope": "user:email"
        }).json()
        email = result[0].get("email", "")
    userresult = model.getuser(email)
    if userresult:
        resp = make_response(redirect(url_for('login')))
        token = model.NewToken(userresult)
        resp.set_cookie("accessToken", token.accessToken)
        resp.set_cookie("clientToken", token.clientToken)
        return resp
    cache_redis.set(".".join(["OAuth", "github", "response", code]), simplejson.dumps({
        "email": email,
        "face": face,
        "name": r.get("login", ""),
        "bio": r.get("bio", ""),
        "way": "Github"
    }))
    cache_redis.expire(".".join(["OAuth", "github", "response", code]), 180)
    return redirect(url_for('register', code=code))

@app.route("/api/knowledgefruits/textures/info/<path:args>")
def kf_texturesinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(simplejson.dumps({
            "err": "WrongArgs",
            "message": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i] : args.split("/")[i + 1] for i in range(len(args.split("/")))[::2]}
    content = [model.textures.__dict__[i].field == Args[i] for i in Args.keys()][0]
    for i in [model.textures.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    print(content)
    try:
        return Response(simplejson.dumps([
            model.kf_format_textures(i) for i in model.findtextures(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(simplejson.dumps({
            "err": "WrongArgs",
            "message": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)

@app.route("/api/knowledgefruits/profile/info/<path:args>")
def kf_profileinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(simplejson.dumps({
            "err": "WrongArgs",
            "message": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i] : args.split("/")[i + 1] for i in range(len(args.split("/")))[::2]}
    content = [model.profile.__dict__[i].field == Args[i] for i in Args.keys()][0]
    for i in [model.profile.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    print(content)
    try:
        return Response(simplejson.dumps([
            model.kf_format_profile(i) for i in model.findprofile(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(simplejson.dumps({
            "err": "WrongArgs",
            "message": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)

@app.route('/api/knowledgefruits/register')
def register():
    return render_template("register.html")

@app.route('/api/knowledgefruits/login')
def login():
    if request.cookies.get("accessToken"):
        if model.gettoken(request.cookies.get("accessToken")):
            return redirect(url_for("index_manager"))
    return render_template("login.html")

@app.route("/api/knowledgefruits/error")
def service_error():
    return Response(render_template("error.html"), status=int(request.args.get("status", 500)))

@app.route("/api/knowledgefruits/resource", methods=['POST'])
def kapi_resource():
    if request.is_json:
        data = request.json
        sourceId = data.get("sourceId")
        if not sourceId:
            return Response(status=403)
        Data1 = cache_redis.get(".".join(["manager", "session", "resource", "callback", sourceId])).decode()
        if not Data1:
            return Response(status=404)
        return Response(Data1, mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/manager/")
def index_manager():
    resp = make_response(render_template("manager_index.html"))
    if request.cookies.get("accessToken"):
        token = model.gettoken(request.cookies.get("accessToken"))
        if not token:
            return redirect(url_for('service_error', error="提交数据错误", errorMessage="你需要先登录才能访问.", status=403))
        if token.status not in ["0", "1"]:
            return redirect(url_for('service_error', error="登录密匙过期", errorMessage="你需要获取新的登录密匙才能访问.", status=403))
        if token.status == '1':
            newtoken = model.token(
                accessToken=str(uuid.uuid4()).replace("-", ""),
                clientToken=token.clientToken,
                bind=token.bind,
                email=token.email
            )
            newtoken.save()
            token.delete_instance()
            token = newtoken
        if token.accessToken != request.cookies.get("accessToken"):
            resp.set_cookie("accessToken", token.accessToken)
        userresult = model.user.get(model.user.email == token.email)
        try:
            AvailableProfiles = [
                model.format_profile(i, unsigned=True, BetterData=True) for i in model.profile.select().where(model.profile.createby==token.email)
            ]
        except Exception as e:
            if "profileDoesNotExist" == e.__class__.__name__:
                AvailableProfiles = []
        dumpdata = {
            "email": token.email,
            "profiles": AvailableProfiles
        }
        cache_redis.set(".".join(["manager", "session", "resource", "callback", token.accessToken]), simplejson.dumps(dumpdata))
        cache_redis.expire(".".join(["manager", "session", "resource", "callback", token.accessToken]), 60)
    return resp

@app.route("/api/knowledgefruits/user/textures")
def user_textures():
    email = request.args.get("username")
    IReturn = []
    if not email:
        return redirect(url_for('service_error', error="缺少指定参数", errorMessage="你需要传入响应参数才能使用该接口", status=403))
    userresult = model.getuser(email)
    if not userresult:
        return redirect(url_for('service_error', error="错误的参数", errorMessage="你传入的参数不正确", status=403))
    result = model.gettextures_byuserid(userresult.uuid)
    if not result:
        return Response(simplejson.dumps([]), mimetype='application/json; charset=utf-8')
    for i in result:
        IReturn.append({
            "textureid": i.textureid,
            "name": i.photoname,
            "height": int(i),
            "width": int(i),
            "type": i.type,
            "model": i.model,
            "hash": i.hash
        })
    return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/user/textures/accessToken")
def user_textures_at():
    accessToken = request.args.get("accessToken")
    IReturn = []
    if not accessToken:
        return redirect(url_for('service_error', error="缺少指定参数", errorMessage="你需要传入响应参数才能使用该接口", status=403))
    userresult = model.getuser_byaccesstoken(accessToken)
    result = model.gettextures_byuserid(userresult.uuid)
    if not result:
        return Response(simplejson.dumps([]), mimetype='application/json; charset=utf-8')
    for i in result:
        IReturn.append({
            "textureid": i.textureid,
            "name": i.photoname,
            "height": int(i.height),
            "width": int(i.width),
            "type": i.type,
            "model": i.model,
            "hash": i.hash
        })
    return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

#####################
@app.route("/texture/<image>", methods=['GET'])
def imageview(image):
    try:
        with open(os.getcwd() + "/data/texture/" + image + '.png', "rb") as f:
            image = f.read()
    except FileNotFoundError:
        raise NotFound(
            description="SkinNotFound",
            response=Response(simplejson.dumps(
                {
                    "error" : "Not Found",
                    'errorMessage' : "无法找到相应文件."
                }
            ), mimetype='application/json; charset=utf-8', status=404)
        )
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
            return redirect(url_for('service_error',
                error="皮肤请求类型错误",
                errorMessage="无法抓取该类型皮肤文件的head部分",
                status=403
            ))
        image = base.gethead_skin(filename)
    except FileNotFoundError:
        return redirect(url_for('service_error',
            error="Not Found",
            errorMessage="无法找到相应文件.",
            status=404)
        )
    return Response(image, mimetype='image/png')


if __name__ == '__main__':
    #threading.Thread(target=crontab.start).start()
    #model.db['cache'].create_tables([model.ms_serverjoin])
    # Drop Cache Table
    #model.ms_serverjoin.delete().execute()
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
    app.run(**config.AdditionalParameters)
