import peewee
import time
from datetime import datetime
from time import strftime
import base
import os
import simplejson
import base64
import uuid
import rsa
import binascii
import password
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import hashlib

config = base.Dict2Object(simplejson.loads(open("./data/config.json").read()))

db = {}
db['global'] = peewee.__dict__[config.database.type](config.database.connect_info.global_db, **config.database.globalinfo)
class user(peewee.Model):
    uuid = peewee.CharField(default=str(uuid.uuid4()).replace("-", ""))
    email = peewee.CharField()
    password = peewee.CharField()
    passwordsalt = peewee.CharField()
    #playername = peewee.CharField()
    selected = peewee.CharField(null=True)

    class Meta:
        database = db['global']

class token(peewee.Model):
    accessToken = peewee.CharField()
    clientToken = peewee.CharField()
    status = peewee.CharField(default=0)
    bind = peewee.CharField(null=True)
    email = peewee.CharField()
    setuptime = peewee.TimestampField(default=time.time())

    class Meta:
        database = db['global']

class profile(peewee.Model):
    format_id = peewee.CharField(max_length=32, default=str(uuid.uuid4()).replace('-',''))
    uuid = peewee.CharField(max_length=32)
    name = peewee.CharField()
    skin = peewee.CharField(null=True)
    cape = peewee.CharField(null=True)
    time = peewee.CharField(default=str(int(time.time())))
    createby = peewee.CharField() # 谁创建的角色?  邮箱
    class Meta:
        database = db['global']

class textures(peewee.Model):
    userid = peewee.CharField(32) # 标识上传者
    textureid = peewee.CharField(default=str(uuid.uuid4()).replace("-", ""))
    photoname = peewee.CharField()
    height = peewee.IntegerField(default=32)
    width = peewee.IntegerField(default=64)
    type = peewee.CharField(default='SKIN')
    model = peewee.CharField(default='STEVE')
    hash = peewee.CharField()

    class Meta:
        database = db['global']

'''
class banner(peewee.Model):
    email = peewee.CharField()
    accessToken = peewee.CharField(max_length=32, null=True)
    profileuuid = peewee.CharField()
    inittime = peewee.TimestampField(default=int(time.time())) # time.mktime(datetime.now().timetuple())
    timeout = peewee.TimestampField()
    class Meta:
        database = db['global']
'''

def format_texture(profile, unMetaData=False, BetterData=False):
    try:
        data_skin = textures.select().where(textures.textureid==profile.skin)
    except Exception as e:
        if "texturesDoesNotExist" == e.__class__.__name__:
            data_skin = {}
    try:
        data_cape = textures.select().where(textures.textureid==profile.cape)
    except Exception as e:
        if "texturesDoesNotExist" == e.__class__.__name__:
            data_cape = {}
    #print(type(data.time))
    if BetterData:
        if not [True, False][getskintype_profile(profile) == "SKIN" and getskinmodel_profile(profile) == "ALEX"]:
            unMetaData = False
        else:
            unMetaData = True
    IReturn = {
        "timestamp" : base.gettimestamp(profile.time),
        'profileId' : profile.format_id,
        'profileName' : profile.name,
        'textures' : {}
    }
    if data_skin:
        IReturn['textures'].update({
            i.type : {
                "url" : config.HostUrl + "/texture/" + i.hash,
                "metadata" : {
                    'model' : {"STEVE": 'default', "ALEX": 'slim'}[i.model]
                }
            } for i in data_skin
        })
    if data_cape:
        IReturn['textures'].update({
            i.type : {
                "url" : config.HostUrl + "/texture/" + i.hash,
                "metadata" : {}
            } for i in data_cape
        })
    if unMetaData:
        for i in IReturn['textures'].keys():
            del IReturn['textures'][i]["metadata"]
    return IReturn

def getuser_byaccesstoken(accessToken):
    nowtoken = gettoken(accessToken)
    if not nowtoken:
        return False
    return user.get(user.email == nowtoken.email)

def gettexture(textureid):
    try:
        result = textures.select().where(textures.textureid == textureid)
    except Exception as e:
        if "profileDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return result
'''
def format_texture_raw(id_skin, id_cape=None, unMetaData=False, BetterData=False):
    skin = gettexture(id_skin)
    if id_cape:
        cape = gettexture(id_cape)
        if cape.type != "CAPE":
            return False
    else:
        cape = {}
    if skin.type != "SKIN":
        return False
    if BetterData:
        if not [True, False][skin.model == "ALEX"]:
            unMetaData = False
        else:
            unMetaData = True
    IReturn = {
        "timestamp" : int(profile.time),
        'profileId' : profile.format_id,
        'profileName' : profile.name,
        'textures' : {}
    }
    if skin:
        IReturn['textures'].update({
            i.type : {
                "url" : config.HostUrl + "/texture/" + i.hash,
                "metadata" : {
                    'model' : {"STEVE": 'default', "ALEX": 'slim'}[i.model]
                }
            } for i in skin
        })
    if cape:
        IReturn['textures'].update({
            i.type : {
                "url" : config.HostUrl + "/texture/" + i.hash,
                "metadata" : {}
            } for i in cape
        })
    if unMetaData:
        for i in IReturn['textures'].keys():
            del IReturn['textures'][i]["metadata"]
    return IReturn
'''
def getskintype_profile(iprofile):
    if not iprofile.skin:
        return False
    texture = textures.get(textures.textureid == iprofile.skin)
    return texture.type

def getskinmodel_profile(iprofile):
    if not iprofile.skin:
        return False
    texture = textures.get(textures.textureid == iprofile.skin)
    return texture.model

def gettexture_hash(Hash):
    if not Hash:
        return False
    texture = textures.get(textures.hash == Hash)
    return texture

def format_profile(profile, unsigned=False, Properties=False, unMetaData=False, BetterData=False):
    def sign_self(data, key_file):
        key_file = open(key_file, 'r').read()
        key = rsa.PrivateKey.load_pkcs1(key_file.encode('utf-8'))
        return bytes(base64.b64encode(rsa.sign(data.encode("utf-8"), key, 'SHA-1'))).decode("utf-8")
    if BetterData:
        if not [True, False][getskintype_profile(profile) == "SKIN" and getskinmodel_profile(profile) == "ALEX"]:
            unMetaData = False
        else:
            unMetaData = True
    textures = simplejson.dumps(format_texture(profile, unMetaData))
    IReturn = {
        "id" : profile.format_id,
        "name" : profile.name,
    }
    if Properties:
        IReturn['properties'] = [
            {
                "name": 'textures',
                'value' : base64.b64encode(textures.encode("utf-8")).decode("utf-8"),
            }
        ]
        if not unsigned:
            for i in range(len(IReturn['properties'])):
                IReturn['properties'][i]['signature'] = sign_self(IReturn['properties'][i]['value'], "./data/rsa.pem")
    return IReturn

def NewToken(user, ClientToken=str(uuid.uuid4()).replace("-", "")):
    Token = token(accessToken=str(uuid.uuid4()).replace("-", ""), clientToken=ClientToken, bind=user.selected, email=user.email)
    Token.save()
    return Token

def nosignuuid():
    return str(uuid.uuid4()).replace("-", "")

def AutoRefrush(Token):
    # 如果炸了,自动刷新(but status != 2),没有则返回原值
    if Token.status == "2":
        return False
    if Token.status == "0":
        return Token
    ClientToken = Token.clientToken
    AccessToken = nosignuuid()
    ReturnToken = token(accessToken=AccessToken, clientToken=ClientToken, bind=Token.bind, email=Token.email)
    ReturnToken.save()
    return ReturnToken

def is_validate(AccessToken, ClientToken=None):
    try:
        if not ClientToken:
            try:
                result = token.get(token.accessToken == AccessToken)
            except Exception as e:
                if "tokenDoesNotExist" == e.__class__.__name__:
                    return False
        else:
            try:
                result = token.get(token.accessToken == AccessToken & token.clientToken == ClientToken)
            except Exception as e:
                if "tokenDoesNotExist" == e.__class__.__name__:
                    result = token.get(token.accessToken == AccessToken)
    except Exception as e:
        if "tokenDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        if result.status in [2,1]:
            return False
        else:
            return True

def gettoken(AccessToken, ClientToken=None):
    try:
        if not ClientToken:
            try:
                result = token.get(token.accessToken == AccessToken)
            except Exception as e:
                if "tokenDoesNotExist" == e.__class__.__name__:
                    return False
        else:
            try:
                result = token.get(token.accessToken == AccessToken & token.clientToken == ClientToken)
            except Exception as e:
                if "tokenDoesNotExist" == e.__class__.__name__:
                    result = token.get(token.accessToken == AccessToken)
    except Exception as e:
        if "tokenDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        if result.status in [2,1]:
            return False
        else:
            return result

def getprofile(name):
    try:
        result = profile.select().where(profile.name == name)
    except Exception as e:
        if "profileDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return result

def getuser(email):
    try:
        result = user.get(user.email == email)
    except Exception as e:
        if "userDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return result

def gettextures_byuserid(userid):
    try:
        result = textures.select().where(textures.userid == userid)
    except Exception as e:
        if "userDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return result

def findprofilebyid(fid):
    try:
        result = profile.select().where(profile.format_id == fid)
    except Exception as e:
        if "profileDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return result.get()

def format_user(user):
    return {
        'id' : user.uuid,
        'properties' : []
    }

def NewProfile(Playername, User, Png, Type='SKIN', Model="STEVE"):
    Email = User.email
    p = profile(uuid=base.OfflinePlayerUUID(Playername).replace('-',''), name=Playername, hash=base.PngBinHash(config.texturepath + Png), createby=Email, type=Type, model=Model)
    print(config.texturepath + Png)
    os.rename(config.texturepath + Png, config.texturepath + base.PngBinHash(config.texturepath + Png) + ".png")
    p.save()

def NewUser(email, passwd):
    salt = base.CreateSalt(length=8)
    user(
        email=email,
        password=password.crypt(passwd, salt),
        passwordsalt=salt
    ).save()

def CreateProfile(name, createby, SKIN=None, CAPE=None):
    OfflineUUID = base.OfflinePlayerUUID(name).replace("-", "")
    db = profile(uuid=OfflineUUID, name=name, createby=createby, skin=SKIN, cape=CAPE)
    db.save()

def NewTexture(name, user, photoname, Type="SKIN", model="STEVE"):
    data = textures(userid=user.uuid, photoname=photoname, type=Type, model=model, hash=base.PngBinHash(name))
    data.save()
    return data.textureid

if __name__ == '__main__':
    #db['global'].create_tables([profile, token, user, textures])
    #NewUser("test@gmail.com", "asd123456")
    #NewUser("1846913566@qq.com", "asd123456")
    #NewUser("test3@to2mbn.org", "asd123456")
    #Chenwe_i_lin_skin = NewTexture("./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png",user.get(user.email == "1846913566@qq.com"),photoname="Chenwe_i_lin-skin")
    #Chenwe_i_lin_cape = NewTexture("./data/texture/8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee.png",user.get(user.email == "1846913566@qq.com"),photoname="Chenwe_i_lin-cape",Type="CAPE")
    #testplayer_skin = NewTexture("./data/texture/490bd08f1cc7fce67f2e7acb877e5859d1605f4ffb0893b07607deae5e05becc.png",user.get(user.email == "test3@to2mbn.org"),photoname="testplayer-skin",model="ALEX")
    #testplayer3_cape = NewTexture("./data/texture/ddcf7d09723e799e59d7f19807d0bf5e3a2c044ce17e76a48b8ac4d27c0b16e0.png",user.get(user.email == "test3@to2mbn.org"),photoname="testplayer3-cape",Type="CAPE")
    #CreateProfile("Chenwe_i_lin","1846913566@qq.com",SKIN="74da44e9a1404ab79312dbc89b51a9f0",CAPE="11fdd8a1db50406a894f0a3a08295bd7")
    #CreateProfile("testplayer","test3@to2mbn.org",SKIN="dce9f17b2e8045febb75d80020bbfd53")
    CreateProfile("testplayer1","test3@to2mbn.org",CAPE="092fc3923f1144239a4183b34d1dc082")