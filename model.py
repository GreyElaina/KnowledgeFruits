import peewee
import time
from datetime import datetime
from time import strftime
import config
import base
import os
import simplejson
import base64
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import uuid
import rsa
import binascii
'''
dbinfo = config.dbtype[config.database['type']]'''
db = {}
'''
for i in dbinfo['attrs']:
    for ii in dbinfo['attr'][i].keys():
        db[ii] = dbinfo['class'](**{i: dbinfo['attr'][i][ii]()}, **dbinfo['templates']())'''
db['global'] = peewee.SqliteDatabase("./data/global.db")
db['cache'] = peewee.SqliteDatabase("./data/cache.db")

class db_user(peewee.Model):
    email = peewee.CharField()
    password = peewee.CharField()
    passwordsalt = peewee.CharField()
    #playername = peewee.CharField()

    class Meta:
        database = db['global']

class db_token(peewee.Model):
    accessToken = peewee.CharField()
    clientToken = peewee.CharField()
    status = peewee.CharField(default=0)
    bind = peewee.CharField()
    setuptime = peewee.TimestampField(default=time.time())

    class Meta:
        database = db['global']

class db_profile(peewee.Model):
    format_id = peewee.CharField(max_length=32, default=str(uuid.uuid4()).replace('-',''))
    uuid = peewee.CharField(max_length=32)
    name = peewee.CharField()
    type = peewee.CharField(default='SKIN')
    model = peewee.CharField(default='STEVE')
    hash = peewee.CharField()
    time = peewee.CharField(default=str(int(time.time())))
    createby = peewee.CharField() # 谁创建的角色?  邮箱

    class Meta:
        database = db['global']

class ms_serverjoin(peewee.Model):
    AccessToken = peewee.CharField(32)
    SelectedProfile = peewee.CharField()
    ServerID = peewee.CharField()
    RemoteIP = peewee.CharField(16, default='0.0.0.0')
    time = peewee.CharField(default=time.time())
    Out_timed = peewee.BooleanField(default=False)

    class Meta:
        database = db['cache']

def CreateProfile(profile, pngname):
    OfflineUUID = base.OfflinePlayerUUID(profile.name)
    Name = profile.name
    hashvalue = base.PngBinHash(config.texturepath + pngname)
    db = db_profile(uuid=OfflineUUID, name=Name, hash=hashvalue)
    db.save()
    os.rename(config.texturepath + pngname, config.texturepath + hashvalue + ".png")

def format_texture(profile):
    OfflineUUID = base.OfflinePlayerUUID(profile.name).replace("-",'')
    db_data = db_profile.get(uuid=OfflineUUID)
    db_datas = db_profile.select().where(db_profile.uuid==OfflineUUID)
    print(type(db_data.time))
    return {
        "timestamp" : round(float(db_data.time)),
        'profileId' : db_data.uuid.replace("-", ""),
        'profileName' : db_data.name,
        'textures' : {
            i.type : {
                "url" : config.url + "texture/" + i.hash,
                "metadata" : {
                    'model' : {"STEVE": 'default', "ALEX": 'slim'}[i.model]
                } if i.type == 'SKIN' else {}
            } for i in db_datas
        }
    }

def format_profile(profile, unsigned=False):
    def sha1withrsa(text):
        key = open("./data/rsa.pem").read()
        signature = rsa.sign(text, rsa.PrivateKey.load_pkcs1(key), 'SHA-1')
        return binascii.hexlify(signature)
    OfflineUUID = base.OfflinePlayerUUID(profile.name).replace("-",'')
    usermodel = db_profile.get(uuid=OfflineUUID)
    textures = simplejson.dumps(format_texture(profile))
    IReturn = {
        "id" : usermodel.format_id,
        "name" : profile.name,
        "properties" : [
            {
                "name":'textures',
                'value' : base64.b64encode(textures.encode("utf-8")),
            }
        ]
    }
    if unsigned == False:
        IReturn['properties'][0]['signature'] = sha1withrsa(base64.b64encode(textures.encode("utf-8")))
    return IReturn

def format_user(user):
    return {
        'id' : base.OfflinePlayerUUID(user.email).replace('-',''),
        "properties" : []
    }

def NewProfile(Playername, User, Png):
    Email = User.email
    db_p = db_profile(uuid=base.OfflinePlayerUUID(Playername).replace('-',''), name=Playername, hash=base.PngBinHash(config.texturepath + Png), createby=Email)
    print(config.texturepath + Png)
    os.rename(config.texturepath + Png, config.texturepath + base.PngBinHash(config.texturepath + Png))
    db_p.save()

if __name__ == '__main__':
    NewProfile("Chenwe_i_lin1", db_user.get(email='1846913566@qq.com'), "skin.png")