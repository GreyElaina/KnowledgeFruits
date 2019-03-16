from flask import Flask, url_for, Response, request, abort, render_template, session, redirect
import peewee
import time
import datetime
from flask.helpers import make_response
import model
import base
import password
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
from werkzeug.exceptions import HTTPException, NotFound
import simplejson
from flask_apscheduler import APScheduler
from os.path import exists as FileExists
from werkzeug.contrib.fixers import LighttpdCGIRootFix
import pydblite
import base64
import os
from urllib.parse import urlparse

config = base.Dict2Object(simplejson.loads(open("./data/config.json").read()))

app = Flask(__name__)
app.config['SECRET_KEY'] = config.salt
#app.config['UPLOAD_FOLDER'] = os.getcwd() + "/data/texture/"
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
    for i in model.db_token.select().where(model.db_token.status == 0 | model.db_token.status == 1):
        OutTime(i)

def DeleteDisabledToken(): # 删除失效Token(token.status == 2)
    model.db_token.delete().where(model.db_token.status == 2).execute()

def ChangeItemStatus():
    for i in model.ms_serverjoin.select().where(model.ms_serverjoin.Out_timed == False):
        if int(time.time()) - round(float(i.time)) >= config.Outtime:
            i.Out_timed = True
            i.save()

def DeleteOuttimeItem():
    model.ms_serverjoin.delete().where(model.ms_serverjoin.Out_timed == True).execute()

app.config.from_object(FlaskConfig())
crontab = APScheduler()
crontab.init_app(app)
crontab.start()
cache = {
    'Login_randomkeys' : {}
}
limiter = Limiter(headers_enabled=True, default_limits=["1/second"])
limit = limiter.limit("1/second", key_func=get_remote_address)

@app.errorhandler(429)
def ratelimit_handler(e):
    return Response(status=403)


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
@limit
@app.route(config.const.base + '/authserver/authenticate', methods=['POST'])
def authenticate():
    IReturn = {}
    if request.is_json:
        data = request.json
        try:
            user = model.db_user.get(model.db_user.email==data['username'])
        except Exception as e:
            if "db_userDoesNotExist" == e.__class__.__name__:
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
            
            Token = model.db_token(accessToken=AccessToken, clientToken=ClientToken, bind=user.selected, email=user.email)
            Token.save() # 颁发Token
            try:
                AvailableProfiles = [
                    model.format_profile(i, unsigned=True) for i in model.db_profile.select().where((model.db_profile.createby==user.email) & (model.db_profile.ismain==True)).group_by(model.db_profile.uuid)
                ]
            except Exception as e:
                if "db_tokenDoesNotExist" == e.__class__.__name__:
                    AvailableProfiles = []

            try:
                SelectedProfile = model.format_profile(model.db_profile.get(uuid=user.selected), unsigned=True)
            except Exception as e:
                if "db_tokenDoesNotExist" == e.__class__.__name__:
                    SelectedProfile = {}

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
        print(r"data:", data)
        Can = False
        AccessToken = data['accessToken']
        ClientToken = data['clientToken'] if 'clientToken' in data else str(uuid.uuid4()).replace("-", "")
        try:
            if 'clientToken' in data:
                OldToken = model.db_token.get(accessToken=AccessToken, clientToken=ClientToken)
            else:
                OldToken = model.db_token.get(accessToken=AccessToken)
        except Exception as e:
            if "db_tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        User = model.db_user.get(email=OldToken.email)
        
        TokenSelected = OldToken.bind
        if TokenSelected:
            TokenProfile = model.db_profile.get(uuid=TokenSelected)
        else:
            TokenProfile = {}
        if 'selectedProfile' in data:
            PostProfile = data['selectedProfile']
            # 验证客户端提供的角色信息
            try:
                needuser = model.db_profile.get(format_id=PostProfile['id'], name=PostProfile['name'])
            except Exception as e:
                if "db_profileDoesNotExist" == e.__class__.__name__:
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

        NewToken = model.db_token(accessToken=str(uuid.uuid4()).replace('-', ''), clientToken=ClientToken, email=OldToken.email, bind=TokenSelected)
        NewToken.save()
        OldToken.delete_instance()
        IReturn = {
            "accessToken" : NewToken.accessToken,
            'clientToken' : ClientToken,
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
                result = model.db_token.get(model.db_token.accessToken == AccessToken)
            else:
                result = model.db_token.get(model.db_token.accessToken == AccessToken, model.db_token.clientToken == ClientToken)
        except Exception as e:
            if "db_tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            if result.status in [2,1]:
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
        #print("tesst:", data)
        try:
            if ClientToken == None:
                try:
                    result = model.db_token.get(model.db_token.accessToken == AccessToken)
                except Exception as e:
                    if "db_tokenDoesNotExist" == e.__class__.__name__:
                        return Response(status=204)
            else:
                try:
                    result = model.db_token.get(model.db_token.accessToken == AccessToken & model.db_token.clientToken == ClientToken)
                except Exception as e:
                    if "db_tokenDoesNotExist" == e.__class__.__name__:
                        result = model.db_token.get(model.db_token.accessToken == AccessToken)
        except Exception as e:
            if "db_tokenDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid token."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
                #return Response(status=204)
            raise e
        else:
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
            result = model.db_user.get(model.db_user.email == email)
        except Exception as e:
            if "db_userDoesNotExist" == e.__class__.__name__:
                error = {
                    'error' : "ForbiddenOperationException",
                    'errorMessage' : "Invalid credentials. Invalid username or password."
                }
                return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            raise e
        else:
            if password.crypt(passwd, salt=result.passwordsalt) == result.password:
                try:
                    model.db_token.delete().where(model.db_token.bind == result.selected).execute()
                except Exception as e:
                    if "db_userDoesNotExist" == e.__class__.__name__:
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
                    result = model.db_profile.get(uuid=token.bind)
                except Exception as e:
                    if "db_profileDoesNotExist" == e.__class__.__name__:
                        return Response(status=404)
                    raise e
            else:
                return Response(simplejson.dumps({
                    'error' : "ForbiddenOperationException",
                    "errorMessage" : "Invalid token."
                }), status=403, mimetype="application/json; charset=utf-8")
            playeruuid = model.db_profile.get(name=result.name).format_id.replace("-", "")
            if data['selectedProfile'] == playeruuid:
                sj = model.ms_serverjoin(
                    AccessToken=AccessToken,
                    SelectedProfile=data['selectedProfile'],
                    ServerID=data['serverId'],
                    RemoteIP=request.remote_addr
                )
                sj.save()
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
    try:
        JoinInfo = model.ms_serverjoin.get(ServerID=ServerID)
        TokenInfo = model.db_token.get(accessToken=JoinInfo.AccessToken)
        ProfileInfo = model.db_profile.get(uuid=TokenInfo.bind, name=PlayerName)
    except Exception as e:
        if "DoesNotExist" in e.__class__.__name__:
            return Response(status=204)
        raise e

    Successful = PlayerName == ProfileInfo.name and [True, RemoteIP == JoinInfo.RemoteIP][bool(RemoteIP)]
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
    print(args)
    if 'unsigned' in args:
        signed = True if args['unsigned'] == 'true' else False
        #signed = False if args['unsigned'] == 'false' else True
        if args['unsigned'] == 'false':
            try:
                result = model.db_profile.get(format_id=getuuid)
                IReturn = model.format_profile(
                    #model.db_user.get(model.db_user.playername == model.db_profile.get(format_id=getuuid).name),
                    result,
                    Properties=True,
                    unsigned=False,
                    unMetaData=[True, False][result.type == "SKIN" and result.model == "ALEX"]
                )
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    return Response(status=204)
                raise e
            return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
        if args['unsigned'] == 'true':
            try:
                result = model.db_profile.get(format_id=getuuid)
                IReturn = model.format_profile(
                    #model.db_user.get(model.db_user.playername == model.db_profile.get(format_id=getuuid).name),
                    result,
                    Properties=True,
                    unsigned=True,
                    unMetaData=[True, False][result.type == "SKIN" and result.model == "ALEX"]
                )
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    return Response(status=204)
                raise e
            return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
    else:
        try:
            result = model.db_profile.get(format_id=getuuid)
            IReturn = model.format_profile(
                #model.db_user.get(model.db_user.playername == model.db_profile.get(format_id=getuuid).name),
                result,
                Properties=True,
                unsigned=True,
                unMetaData=[True, False][result.type == "SKIN" and result.model == "ALEX"]
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
        print(request.json)
        IReturn = list()
        for i in range(config.ProfileSearch.MaxAmount - 1):
            try:
                IReturn.append(model.format_profile(model.db_profile.select().where((model.db_profile.name==data[i]) & (model.db_profile.ismain == True)).get(), unsigned=True))
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    continue
        print(IReturn)
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
        }
    }), mimetype='application/json; charset=utf-8')

@app.route("/api/knowledgefruits/login/randomkey", methods=['POST'])
def kf_login_randomkey():
    if request.is_json:
        data = request.json
        Randomkey = password.CreateSalt(length=8)
        authid = data['authid'] if 'authid' in data else str(uuid.uuid4()).replace('-', '')
        user_result = model.getuser(data['username']).get()
        salt = user_result.passwordsalt
        if user_result:
            IReturn = {
                "authId" : authid,
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt
            }
            cache[authid] = {
                "HashKey" : Randomkey,
                "username" : user_result.email,
                "salt" : salt,
                "VerifyValue" : user_result.password,
                "authId" : authid
            }
            return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)

@app.route("/api/knowledgefruits/login/randomkey/verify", methods=['POST'])
def kf_login_verify():
    if request.is_json:
        data = request.json
        try:
            cache_result = cache[data['authId']]
        except KeyError:
            return Response(status=403)
        else:
            user_result = model.getuser(cache_result['username']).get()
            if user_result:
                AuthRequest = password.crypt(user_result.password, cache_result['HashKey'])
                if AuthRequest == data['Password']:
                    Token = model.db_token(accessToken=str(uuid.uuid4()).replace("-", ""), clientToken=str(uuid.uuid4()).replace("-", ""), bind=user_result.selected, email=user_result.email)
                    Token.save() # 颁发Token

                    IReturn = {
                        "accessToken" : Token.accessToken,
                        "clientToken" : Token.clientToken
                    }
                    del cache[data['authId']]
                    return Response(simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')
                else:
                    error = {
                        'error' : "ForbiddenOperationException",
                        'errorMessage' : "Invalid credentials. Invalid username or password."
                    }
                    del cache[data['authId']]
                    return Response(simplejson.dumps(error), status=403, mimetype='application/json; charset=utf-8')
            else:
                del cache[data['authId']]
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
                user = model.getuser(token.email).get()
                if password.crypt(decrypt_message, user.passwordsalt) == user.password:
                    return Response(status=204)
                newsalt = base.CreateSalt(length=8)
                newpassword = password.crypt(decrypt_message, newsalt)
                user.password = newpassword
                user.passwordsalt = newsalt
                user.save()
                #开始否决所有的Token
                model.db_token.delete().where(model.db_token.email == user.email).execute()
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

@app.route('/api/knowledgefruits/profile/add', methods=['POST'])
def profileadd():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")
        if not ClientToken:
            token_result_boolean = model.is_validate(AccessToken)
            token = model.gettoken(AccessToken)
        else:
            token_result_boolean = model.is_validate(AccessToken, ClientToken)
            token = model.gettoken(AccessToken, ClientToken)
        if token_result_boolean:
            #Token有效
            Email = token.email
            if re.match(base.StitchExpression(config.reMatch.PlayerName), data.get("PlayerName")):
                PlayerName = data.get(PlayerName)
                result = model.db_profile(
                    uuid=base.OfflinePlayerUUID(PlayerName).replace("-", ""),
                    name=PlayerName,
                    createby=Email
                )
                result.save()
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

if __name__ == '__main__':
    #threading.Thread(target=crontab.start).start()
    #model.db['cache'].create_tables([model.ms_serverjoin])
    # Drop Cache Table
    #model.ms_serverjoin.delete().execute()
    if FileExists('./data/global.db'):
        model.db['global'].create_tables([model.db_profile, model.db_token, model.db_user])
        model.db['global'].create_tables([model.ms_serverjoin])
    if False in [FileExists(config.KeyPath.Private), FileExists(config.KeyPath.Public)]:
        import rsa
        (public, private) = rsa.newkeys(2048)
        with open(config.KeyPath.Private, 'wb') as f:
            f.write(private.save_pkcs1())
        with open(config.KeyPath.Public, 'wb') as f:
            f.write(public.save_pkcs1())
    app.wsgi_app = LighttpdCGIRootFix(app.wsgi_app)
    app.run(**config.AdditionalParameters)