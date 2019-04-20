from base import config, cache, app, Token
from flask import request, Response
import json
import uuid
import model
import utils
from urllib.parse import parse_qs, urlencode, urlparse
import password
import time

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
            ClientToken = data.get("clientToken", str(uuid.uuid4()).replace("-",""))
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
            }, ttl=config.TokenTime.RefrushTime * config.TokenTime.TimeRange)

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
        
        if int(time.time()) >= OldToken.get("createTime") + (config.TokenTime.RefrushTime * config.TokenTime.TimeRange):
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
        }, ttl=config.TokenTime.RefrushTime * config.TokenTime.TimeRange)

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
