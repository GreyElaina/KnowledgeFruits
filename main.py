from flask import Flask, url_for, Response
from flask import request, abort
import config
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

app = Flask(__name__)

class FlaskConfig(object):
    JOBS = [
        {
            'id': 'ChangeStatus',
            'func': 'main:CheckTokenStatus',
            'args': (),
            'trigger': 'interval',
            'minutes' : config.ChangeTokenStatus
        },
        {
            'id': 'ClearDisabledTokens',
            'func': 'main:DeleteDisabledToken',
            'args': (),
            'trigger': 'interval',
            'minutes' : config.ClearTokenMinute
        },
        {
            'id': "ChangeItemStatus",
            'func': "main:ChangeItemStatus",
            'args': (),
            'trigger': 'interval',
            'seconds' : config.RunMinute_Change
        },
        {
            'id': "DeleteOuttimeItem",
            'func': "main:DeleteOuttimeItem",
            'args': (),
            'trigger': 'interval',
            'seconds' : config.RunMinute_Delete
        }
    ]

    SCHEDULER_API_ENABLED = True

def OutTime(token):
    '''
    token.status = \
        1 if not config.TokenOutTime['canUse'](time.time() - time.mktime(token.setuptime.timetuple())) else\
        2 if not config.TokenOutTime['NeedF5'](time.time() - time.mktime(token.setuptime.timetuple())) else\
        0
    '''
    if config.TokenOutTime['canUse'](time.time() - time.mktime(token.setuptime.timetuple())):
        token.status = 0
    elif config.TokenOutTime['needF5'](time.time() - time.mktime(token.setuptime.timetuple())):
        token.status = 1
    else:
        token.status = 2
    token.save()
    # 0:可以进行操作
    # 1:只能刷新
    # 2:已经失效,无法执行任何操作

def CheckTokenStatus():
    canuse = model.db_token.select().where(model.db_token.status == 0, model.db_token.status == 1)
    for i in canuse:
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

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=config.limiter_filter['default_limits'])

@limiter.request_filter
def filter_func():
    path_url = request.path
    white_list = config.limiter_filter['whitelist']
    if path_url in white_list:
        return True
    else:
        return False

@app.route(config.const['base'] + '/', methods=['GET'])
def index():
    return Response(simplejson.dumps({
        "meta" : config.IndexMeta,
        "skinDomains": config.SiteDomain,
        "signaturePublickey": open(config.PUBLICKEY, 'r').read()
    }), mimetype='application/json; charset=utf-8')

# /authserver

@app.route(config.const['base'] + '/authserver/authenticate', methods=['POST'])
def authenticate():
    IReturn = {}
    if request.is_json:
        data = request.json
        user = model.db_user.get(email=data['username'])
        SelectedProfile = []
        AvailableProfiles = []
        if password.crypt(data['password'], user.passwordsalt) == user.password:
            # 登录成功.
            ClientToken = data['clientToken'] if "clientToken" in data else str(uuid.uuid4()).replace("-","")
            AccessToken = str(uuid.uuid4()).replace("-","")
            
            Token = model.db_token(accessToken=AccessToken, clientToken=ClientToken, bind=data['username'])
            Token.save() # 颁发Token
            try:
                AvailableProfiles = [model.format_profile(i) for i in model.db_profile.select().where(model.db_profile.createby==data['username'])]
            except Exception as e:
                if "db_tokenDoesNotExist" == e.__class__.__name__:
                    AvailableProfiles = []

            try:
                SelectedProfile = model.format_profile(model.db_profile.get(createby=user.email))
            except Exception as e:
                if "db_tokenDoesNotExist" == e.__class__.__name__:
                    SelectedProfile = []

            IReturn = {
                "accessToken" : AccessToken,
                "clientToken" : ClientToken,
                "availableProfiles" : AvailableProfiles,
                "selectedProfile" : SelectedProfile
            }
            
            if "requestUser" in data:
                if data['requestUser']:
                    IReturn['user'] = model.format_user(user)

        info = make_response(simplejson.dumps(IReturn))
        info.headers['Content-Type'] = 'application/json; charset=utf-8'
        return info
'''
@app.route(config.const['base'] + '/authserver/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.json
        salt = base.CreateSalt(length=12)
        try:
            content = [
                model.db_user.get(email=data['email']),
                model.db_user.get(playername=data['playername']),
                None == re.match(r'^[0-9a-zA-Z\_\-]+(\.[0-9a-zA-Z\_\-]+)*@[0-9a-zA-Z]+(\.[0-9a-zA-Z]+){1,}$', data['email'])
            ]
        except:
            content = []

        if True in content:
            return "FAIL"
        user = model.db_user(
            email=re.match(r'^[0-9a-zA-Z\_\-]+(\.[0-9a-zA-Z\_\-]+)*@[0-9a-zA-Z]+(\.[0-9a-zA-Z]+){1,}$', data['email']).group(),
            password=password.crypt(data['password'], salt),
            passwordsalt=salt
        )
        profile = model.db_profile(
            uuid=base.OfflinePlayerUUID(data['playername']).replace('-',''),
            name=data['playername'],
            hash=base.PngBinHash('./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png')
        )
        profile.save()
        user.save()
        return "OK"
'''
@app.route(config.const['base'] + '/authserver/refresh', methods=['POST'])
def refresh():
    IReturn = {}
    if request.is_json:
        data = request.json
        AccessToken = str(uuid.uuid4()).replace("-","")
        ClientToken = data['clientToken'] if "clientToken" in data else str(uuid.uuid4()).replace("-","")

        try:
            if 'clientToken' in data:
                old = model.db_token.get(model.db_token.clientToken == ClientToken, model.db_token.accessToken == data['accessToken'])
            else:
                old = model.db_token.get(model.db_token.accessToken == data['accessToken'])
        except Exception as e:
            if "db_tokenDoesNotExist" == e.__class__.__name__:
                return Response("Not Found", status=404)
            raise e
        else:
            selectedProfile = model.format_profile(model.db_profile.get(createby=old.bind))
            if "selectedProfile" in data:
                selectedProfile = model.format_profile(model.db_profile.get(name=data['selectedProfile']['name']))
            old.delete_instance()

        new = model.db_token(accessToken=AccessToken, clientToken=ClientToken, bind=model.db_profile.get(name=selectedProfile['name']).createby)
        #playername = selectedProfile['name']
        new.save()

        IReturn = {
            "accessToken" : AccessToken,
            "clientToken" : ClientToken,
            "selectedProfile" : selectedProfile
        }
        if "requestUser" in data:
            if data['requestUser']:
                IReturn['user'] = model.format_user(model.db_user.get(email=model.db_profile.get(name=selectedProfile['name']).createby))

    info = make_response(simplejson.dumps(IReturn))
    info.headers['Content-Type'] = 'application/json; charset=utf-8'
    return info

@app.route(config.const['base'] + "/authserver/validate", methods=['POST'])
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
                return Response("Not Found", status=404)
            raise e
        else:
            if result.status in [2,1]:
                return Response("Token Out-time.Please refresh or relogin.", status=403)
            else:
                return Response(status=204)

@app.route(config.const['base'] + "/authserver/invalidate", methods=['POST'])
def invalidate():
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
                pass
            raise e
        else:
            result.delete_instance()
        finally:
            return Response(status=204)
            
@app.route(config.const['base'] + '/authserver/signout', methods=['POST'])
def signout():
    if request.is_json:
        data = request.json
        email = data['username']
        passwd = data['password']
        try:
            result = model.db_user.get(model.db_user.email == email)
        except Exception as e:
            if "db_userDoesNotExist" == e.__class__.__name__:
                return Response("Not Found", status=404)
            raise e
        else:
            if password.crypt(passwd, salt=result.passwordsalt) == result.password:
                try:
                    model.db_token.delete().where(model.db_token.bind == result.email).execute()
                except Exception as e:
                    if "db_userDoesNotExist" == e.__class__.__name__:
                        return Response("Not Correct Found", status=404)
                    raise e
                else:
                    return Response(status=204)

# /authserver

################

# /sessionserver
@app.route(config.const['base'] + "/sessionserver/session/minecraft/join", methods=['POST'])
def joinserver():
    token = {}
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data['clientToken'] if "clientToken" in data else None

        TokenValidate = False
        try:
            if not ClientToken:
                result = model.db_token.get(model.db_token.accessToken == AccessToken)
            else:
                result = model.db_token.get(model.db_token.accessToken == AccessToken, model.db_token.clientToken == ClientToken)
        except Exception as e:
            if "db_tokenDoesNotExist" == e.__class__.__name__:
                pass
            raise e
        else:
            if not result.status in [2,1]:
                TokenValidate = True
                token = result
        
        if TokenValidate:
            # Token有效
            # email = token.bind
            result = model.db_profile.get(createby=token.bind)
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
                return Response(status=404)
        else:
            return Response(status=404)

@app.route(config.const['base'] + "/sessionserver/session/minecraft/hasJoined", methods=['GET'])
def PlayerHasJoined():
    args = request.args
    ServerID = args['serverId']
    PlayerName = args['username']
    RemoteIP = args['ip'] if 'ip' in args else None
    Successful = False

    try:
        JoinInfo = model.ms_serverjoin.get(ServerID=ServerID)
        TokenInfo = model.db_token.get(accessToken=JoinInfo.AccessToken)
        ProfileInfo = model.db_profile.get(createby=TokenInfo.bind)
    except Exception as e:
        if "DoesNotExist" in e.__class__.__name__:
            return Response(status=204)
        raise e
    
    Successful = PlayerName == ProfileInfo.name and RemoteIP == JoinInfo.RemoteIP if RemoteIP else True
    if Successful:
        return simplejson.dumps(model.format_profile(ProfileInfo))
    else:
        return Response(status=204)

@app.route(config.const['base'] + '/sessionserver/session/minecraft/profile/<getuuid>', methods=['GET'])
def searchprofile(getuuid):
    args = request.args
    unsigned = False
    if 'unsigned' in args:
        if not args['unsigned'] == 'false':
            unsigned = True
    try:
        IReturn = model.format_profile(
            #model.db_user.get(model.db_user.playername == model.db_profile.get(format_id=getuuid).name),
            model.db_profile.get(format_id=getuuid),
            unsigned=unsigned
        )
    except Exception as e:
        if "DoesNotExist" in e.__class__.__name__:
            return Response(status=204)
        raise e
    return Response(response=simplejson.dumps(IReturn), mimetype='application/json; charset=utf-8')

@app.route(config.const['base'] + '/api/profiles/minecraft', methods=['POST'])
def searchmanyprofile():
    if request.is_json:
        data = request.json
        IReturn = []
        for i in data[:config.MaxSearch - 1]:
            try:
                IReturn.append(model.format_profile(i))
            except Exception as e:
                if "DoesNotExist" in e.__class__.__name__:
                    continue
        return simplejson.dumps(IReturn)
    return Response(status=404)

# /sessionserver

#####################

@app.route(config.const['debug'] + "/test", methods=['GET','POST'])
def createprofile():
    # 这里拿来测试
    try:
        profile = model.db_profile(
            uuid=base.OfflinePlayerUUID("Chenwe_i_lin").replace('-',''),
            name="Chenwe_i_lin",
            hash=base.PngBinHash('./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png')
        )
        profile.save()
        return ""
    except Exception as e:
        "DoesNotExist" in e.__class__.__name__

@app.route("/texture/<image>", methods=['GET'])
def imageview(image):
    try:
        with open(config.const['cwd'] + "/data/texture/" + image + '.png', "rb") as f:
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
    if False in [FileExists(config.RSAPEM), FileExists(config.PUBLICKEY)]:
        import rsa
        (public, private) = rsa.newkeys(2048)
        with open(config.RSAPEM, 'w') as f:
            f.write(private.save_pkcs1())
        with open(config.PUBLICKEY, 'w') as f:
            f.write(public.save_pkcs1())

    app.run(**config.runattr)