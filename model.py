import base64
import binascii
import hashlib
import json
import os
import time
import uuid
from datetime import datetime

import peewee
import rsa

import utils
import password
from database import db
from base import config
import Exceptions

class user(peewee.Model):
    uuid = peewee.CharField(default=(lambda: str(uuid.uuid4()).replace("-", "")), index=True)
    username = peewee.CharField(null=True)
    head = peewee.CharField(null=True)
    email = peewee.CharField()
    password = peewee.CharField()
    passwordsalt = peewee.CharField()
    permission = peewee.CharField(default="common_user")
    last_login = peewee.TimestampField(default=None, utc=True)
    last_joinserver = peewee.TimestampField(default=None, utc=True)
    register_time = peewee.TimestampField(default=None, utc=True)

    class Meta:
        database = db['global']

class profile(peewee.Model):
    profile_id = peewee.CharField(max_length=32, default=(lambda: str(uuid.uuid4()).replace("-", "")))
    uuid = peewee.CharField(max_length=32)
    name = peewee.CharField()
    skin = peewee.CharField(null=True)
    cape = peewee.CharField(null=True)
    create_time = peewee.TimestampField(utc=True)
    change_time = peewee.TimestampField(utc=True)
    createby = peewee.CharField() # 谁创建的角色?  uuid
    class Meta:
        database = db['global']

class textures(peewee.Model):
    userid = peewee.CharField(32) # 标识上传者, UUID
    textureid = peewee.CharField(default=(lambda: str(uuid.uuid4()).replace("-", "")))
    photoname = peewee.CharField()
    height = peewee.IntegerField(default=32)
    width = peewee.IntegerField(default=64)
    type = peewee.CharField(default='SKIN')
    model = peewee.CharField(default='STEVE')
    hash = peewee.CharField()
    isPrivate = peewee.BooleanField(default=False)

    class Meta:
        database = db['global']

class banner(peewee.Model):
    user = peewee.CharField()
    profile = peewee.CharField(null=True)
    create_time = peewee.TimestampField(utc=True)
    group = peewee.CharField(default="global")
    until = peewee.TimestampField(default=None, utc=True) # 传入一个utc整数
    class Meta:
        database = db['global']

class group(peewee.Model):
    id = peewee.CharField(default=utils.shortid)
    name = peewee.CharField()
    creater = peewee.CharField()
    manager = peewee.CharField()
    date_out = peewee.TimestampField(default=None, utc=True)
    create_date = peewee.TimestampField(utc=True)
    joinway = peewee.CharField(default="public_join")

    kicked_number = peewee.IntegerField(default=0)
    total_number = peewee.IntegerField(default=0) # 我都不知道我之前写的这是啥....先加上先
    max_number = peewee.IntegerField(default=1)
    total_signout = peewee.IntegerField(default=0)
    
    enable_yggdrasil = peewee.BooleanField(default=True)
    enable_invite = peewee.BooleanField(default=True)
    enable_public_joinhistory = peewee.BooleanField(default=True)
    enable_public_memberlist = peewee.BooleanField(default=False)

    #joinway:
    #1.public_join:任何人可加入
    #2.public_join_review:需要管理员同意
    #3.private:私有组,只能于enable_invite为True时通过内部人员邀请进入

    class Meta:
        database = db['global']

class member(peewee.Model):
    user = peewee.CharField()
    group = peewee.CharField()
    permission = peewee.CharField()
    last_joinserver = peewee.TimestampField(utc=True, null=True)

    kick_others_number = peewee.IntegerField(default=0) # 你难道会记得你踢了几个人吗? KF:you.kick_others_number, 我是统计主义者.
    managedown_number = peewee.IntegerField(default=0) # ouch! 你怎么回事啊,又被下管理了?
    manageup_number = peewee.IntegerField(default=0)
    move_times = peewee.IntegerField(default=0) # 移动次数,指成员的is_disabled变化次数,注意,当加群成功时,is_disabled不会改变.
    permission_used_times = peewee.IntegerField(default=0) # 权利蒙蔽人的双眼,只有数据才能显出其罪恶本质....
    join_times = peewee.IntegerField(default=1) # 你进来几次了?
    be_kicked_times_total = peewee.IntegerField(default=0)
    be_banned_times_user = peewee.IntegerField(default=0)
    be_banned_times_profile = peewee.IntegerField(default=0)
    group_setting_changed_times = peewee.IntegerField(default=0)
    last_changed_group_setting = peewee.IntegerField(default=0)
    
    is_disabled = peewee.BooleanField(default=False) # 我可是...能够记住一切的一切的哦, 不要逃走哦...
    
    # common_user
    # manager
    # super_manager
    class Meta:
        database = db['global']

class review(peewee.Model):
    id = peewee.CharField(default=utils.shortid)
    user = peewee.CharField()
    group = peewee.CharField()
    time = peewee.TimestampField(utc=True)
    extra = peewee.CharField(null=True)
    isEnable = peewee.BooleanField(default=True)
    isAccessed = peewee.BooleanField(default=False)

    class Meta:
        database = db['global']

class message(peewee.Model):
    messageid = peewee.CharField(default=utils.shortid)
    from_ = peewee.CharField(default="KnowledgeFruits Daemon", column_name='from')
    to = peewee.CharField()
    is_read = peewee.BooleanField(default=False)
    
    title = peewee.CharField()
    body = peewee.CharField()
    extra = peewee.CharField(null=True)

    class Meta:
        database = db['global']

class setting(peewee.Model):
    item = peewee.CharField()
    value = peewee.CharField()
    last_value = peewee.CharField(null=True)
    change_date = peewee.TimestampField(utc=True)
    changer = peewee.CharField(null=True)

    class Meta:
        database = db['global']

class log_yggdrasil(peewee.Model):
    operational = peewee.CharField() # 操作
    user = peewee.CharField(null=True)
    profile = peewee.CharField(null=True)
    otherargs = peewee.CharField(null=True)
    IP = peewee.CharField()
    time = peewee.TimestampField(utc=True)
    successful = peewee.BooleanField(default=True)

    class Meta:
        database = db['log']

class log_kf(peewee.Model):
    operational = peewee.CharField() # 操作
    user = peewee.CharField(null=True)
    profile = peewee.CharField(null=True)
    otherargs = peewee.CharField(null=True)
    IP = peewee.CharField()
    time = peewee.TimestampField(utc=True)

    class Meta:
        database = db['log']

def format_texture(profile, unMetaData=False, BetterData=False):
    data_skin = textures.select().where(textures.textureid==profile.skin)
    data_cape = textures.select().where(textures.textureid==profile.cape)
    #print(type(data.time))
    if BetterData:
        if not [True, False][getskintype_profile(profile) == "SKIN" and getskinmodel_profile(profile) == "ALEX"]:
            unMetaData = False
        else:
            unMetaData = True
    IReturn = {
        "timestamp" : utils.gettimestamp(profile.create_time),
        'profileId' : profile.profile_id,
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

def gettexture(textureid):
    try:
        result = textures.select().where(textures.textureid == textureid).get()
    except textures.DoesNotExist:
        return False
    else:
        return result

def gettexture_photoname(name):
    try:
        result = textures.select().where(textures.photoname == name).get()
    except textures.DoesNotExist:
        return False
    else:
        return result

def getskintype_profile(iprofile):
    if not iprofile.skin:
        return False
    texture = textures.get(textures.textureid == iprofile.skin)
    return texture.type

def kf_format_group_public(g: group):
    return {
        "id": g.id,
        "name": g.name,
        "creater": g.creater,
        "manager": g.manager,
        "createTime": g.create_date.timestamp(),
        "joinway": g.joinway
    }

def getskinmodel_profile(iprofile):
    if not iprofile.skin:
        return False
    texture = textures.get(textures.textureid == iprofile.skin)
    return texture.model

def isBanned(user, group="global"):
    ban_info = banner.select().where(banner.user == user.uuid)
    if ban_info:
        for i in ban_info:
            if time.time() < i.until.timestamp():
                break
        else:
            return False
        return True
    else:
        return False

def gettexture_hash(Hash):
    if not Hash:
        return False
    try:
        texture = textures.get(textures.hash == Hash)
    except textures.DoesNotExist:
        return False
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
    textures = json.dumps(format_texture(profile, unMetaData))
    IReturn = {
        "id" : profile.profile_id,
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

def getprofile_id_name(profileid, name):
    try:
        result = profile.select().where((profile.name == name) & (profile.profile_id == profileid))
    except profile.DoesNotExist:
        return False
    else:
        return result

def nosignuuid():
    return str(uuid.uuid4()).replace("-", "")

def getuser_uuid(uuid):
    try:
        result = user.get(user.uuid == uuid)
    except user.DoesNotExist:
        return False
    else:
        return result

def getprofile(name):
    try:
        result = profile.select().where(profile.name == name)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getprofile_uuid(uuid):
    try:
        result = profile.select().where(profile.uuid == uuid)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getprofile_createby(by):
    try:
        result = profile.select().where(profile.createby == by)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getprofile_id(pid):
    try:
        result = profile.select().where(profile.profile_id == pid)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getprofile_uuid(uuid):
    try:
        result = profile.select().where(profile.uuid == uuid)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getprofile_uuid_name(uuid, name):
    try:
        result = profile.select().where(profile.uuid == uuid, profile.name == name)
    except profile.DoesNotExist:
        return False
    else:
        return result

def getuser(email):
    try:
        result = user.get(user.email == email)
    except user.DoesNotExist:
        return False
    else:
        return result

def gettextures_byuserid(userid):
    try:
        result = textures.select().where(textures.userid == userid)
    except user.DoesNotExist:
        return False
    else:
        return result

def findprofilebyid(fid):
    try:
        result = profile.select().where(profile.profile_id == fid)
    except profile.DoesNotExist:
        return False
    else:
        return result.get()

def findprofile(args):
    try:
        result = profile.select().where(args)
    except profile.DoesNotExist:
        return False
    else:
        return result

def findtextures(args):
    try:
        result = textures.select().where(args)
    except textures.DoesNotExist:
        return False
    else:
        return result

def format_user(user):
    return {
        'id' : user.uuid,
        'properties' : []
    }

def kf_format_profile(p):
    skininfo = gettexture(p.skin)
    capeinfo = gettexture(p.cape)
    Info = {
        "profileId": p.profile_id,
        "uuid": p.uuid,
        "name": p.name,
        "textures": {},
        "createby": p.createby
    }
    if skininfo:
        Info['textures']['skin'] = {
            "updater": skininfo.userid,
            "textureid": skininfo.textureid,
            "name": skininfo.photoname,
            "size": {
                "width": skininfo.width,
                "height": skininfo.height
            },
            "type": skininfo.type.lower(),
            "model": {"STEVE": 'default', "ALEX": 'slim'}[skininfo.model],
            "hash": skininfo.hash
        }
    if capeinfo:
        Info['textures']['cape'] = {
            "updater": capeinfo.userid,
            "textureid": capeinfo.textureid,
            "name": capeinfo.photoname,
            "size": {
                "width": capeinfo.width,
                "height": capeinfo.height
            },
            "type": capeinfo.type.lower(),
            "hash": capeinfo.hash
        }
    return Info

def kf_format_textures(t):
    return {
        "updater": t.userid,
        "textureid": t.textureid,
        "name": t.photoname,
        "size": {
            "width": t.width,
            "height": t.height
        },
        "type": t.type.lower(),
        "model": {"STEVE": 'default', "ALEX": 'slim'}[t.model],
        "hash": t.hash
    }

def NewProfile(Playername, User, Png, Type='SKIN', Model="STEVE"):
    Email = User.email
    p = profile(profile_id=(lambda: str(uuid.uuid4()).replace("-", ""))(), uuid=utils.OfflinePlayerUUID(Playername).replace('-',''), name=Playername, hash=utils.PngBinHash(config.texturepath + Png), createby=Email, type=Type, model=Model)
    print(config.texturepath + Png)
    os.rename(config.texturepath + Png, config.texturepath + utils.PngBinHash(config.texturepath + Png) + ".png")
    p.save()

def NewUser(email, passwd):
    salt = utils.CreateSalt(length=8)
    user(
        uuid=(lambda: str(uuid.uuid4()).replace("-", ""))(),
        email=email,
        password=password.crypt(passwd, salt),
        passwordsalt=salt,
        last_login=0.0,
        last_joinserver=0.0,
        register_time=datetime.now()
    ).save()

def CreateProfile(name, createby, SKIN=None, CAPE=None):
    OfflineUUID = utils.OfflinePlayerUUID(name).replace("-", "")
    db = profile(uuid=OfflineUUID, name=name, createby=createby, skin=SKIN, cape=CAPE)
    db.save()

def NewTexture(name, user, photoname, Type="SKIN", model="STEVE"):
    data = textures(textureid=(lambda: str(uuid.uuid4()).replace("-", ""))(), userid=user.uuid, photoname=photoname, type=Type, model=model, hash=utils.PngBinHash(name))
    data.save()
    return data.textureid

def yggdrasil_test():
    #db['global'].create_tables([profile, token, user, textures])
    NewUser("test1@to2mbn.org", "111111")
    NewUser("test2@to2mbn.org", "222222")
    NewUser("test3@to2mbn.org", "333333")
    char1skin = NewTexture("./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png",user.get(user.email == "test2@to2mbn.org"),photoname="character1-skin")
    char1cape = NewTexture("./data/texture/8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee.png",user.get(user.email == "test2@to2mbn.org"),photoname="character1-cape",Type="CAPE")
    character2_skin = NewTexture("./data/texture/490bd08f1cc7fce67f2e7acb877e5859d1605f4ffb0893b07607deae5e05becc.png",user.get(user.email == "test3@to2mbn.org"),photoname="character2-skin",model="ALEX")
    character3_cape = NewTexture("./data/texture/ddcf7d09723e799e59d7f19807d0bf5e3a2c044ce17e76a48b8ac4d27c0b16e0.png",user.get(user.email == "test3@to2mbn.org"),photoname="character3-cape",Type="CAPE")
    CreateProfile("character1","test2@to2mbn.org",SKIN=char1skin,CAPE=char1cape)
    CreateProfile("character2","test3@to2mbn.org",SKIN=character2_skin)
    CreateProfile("character3","test3@to2mbn.org",CAPE=character3_cape)

if __name__ == "__main__":
    #db['global'].create_tables([profile, user, textures, banner, group, member, review, message, setting])
    #NewUser("test1@to2mbn.org", "111111")
    #NewUser("test2@to2mbn.org", "222222")
    #NewUser("test3@to2mbn.org", "333333")
    #char1skin = NewTexture("./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png",user.get(user.email == "test2@to2mbn.org"),photoname="character1-skin")
    #char1cape = NewTexture("./data/texture/8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee.png",user.get(user.email == "test2@to2mbn.org"),photoname="character1-cape",Type="CAPE")
    #character2_skin = NewTexture("./data/texture/490bd08f1cc7fce67f2e7acb877e5859d1605f4ffb0893b07607deae5e05becc.png",user.get(user.email == "test3@to2mbn.org"),photoname="character2-skin",model="ALEX")
    #character3_cape = NewTexture("./data/texture/ddcf7d09723e799e59d7f19807d0bf5e3a2c044ce17e76a48b8ac4d27c0b16e0.png",user.get(user.email == "test3@to2mbn.org"),photoname="character3-cape",Type="CAPE")
    #CreateProfile("character1","test2@to2mbn.org",SKIN="65c15ced19134c4582fae4792a2fdd6c",CAPE="7e534ac7d46e4a8ab38e49eebc08f1bc")
    #CreateProfile("character2","test3@to2mbn.org",SKIN="fa609f3ab7df43e09f1cc4c8a73d4517")
    #CreateProfile("character3","test3@to2mbn.org",CAPE="0160b5a9f07c4f548b1fc64691d09081")
    pass