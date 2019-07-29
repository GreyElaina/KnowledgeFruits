from entrancebar import entrance_file
from urllib.parse import urlunparse, ParseResult
from base64 import b64encode as Base64
from time import time as timestamp_now
import rsa

model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
FormsDict = entrance_file("@/common/FormsDict.py").FormsDict
Config = entrance_file("@/config.py").ConfigObject

# 下划线前是要获取的信息,下划线后是需要给出的信息(多个信息用options代替)
# 这里全部返回Query, 由逻辑处运算并查找信息.

def account_email(email):
    return model.User.select().where(model.User.email == email)

def profiles_userid(userid):
    return model.Profile.select().where(model.Profile.owner == userid)

def account_uuid(uuid):
    return model.User.select().where(model.User.uuid == uuid)

def profile_uuid(uuid):
    return model.Profile.select().where(model.Profile.uuid == uuid)

def profile_name(name):
    return model.Profile.select().where(model.Profile.name == name)

def profile_name_uuid(options):
    original = {
        "uuid": None,
        "name": None
    }
    original.update(options)
    if not any(original):
        return False
    return model.Profile.select().where(
        (model.Profile.uuid == options.get("uuid")) & 
        (model.Profile.name == options.get("name"))
    )

class Format:
    options = FormsDict({
        "unsigned": False,
        "hasProperties": False,
        "hasMetadata": True,
        "enableSmartDecide": False
    })
    def _sign_text(self, data, key_file=Config.ModulesConfig.yggdrasil.SignnatureKeys.Private):
        key_file = open(key_file, 'r').read()
        key = rsa.PrivateKey.load_pkcs1(key_file.encode('utf-8'))
        return bytes(Base64(rsa.sign(data.encode("utf-8"), key, 'SHA-1'))).decode("utf-8")

    def __init__(self, request):
        self.request = request

    def resource(self, row: model.Resource):
        result = {
            "url": urlunparse(ParseResult(
                scheme=self.request.protocol,
                netloc=self.request.host_name,
                path="/resources/{0}".format(row.hash),
                params="",
                query="",
                fragment=""
            ))
        }
        if self.options.hasMetadata:
            result["metadata"] = {
                "model": {"STEVE": 'default', "ALEX": 'slim'}[row.model]
            }
        if self.options.enableSmartDecide and row.model == "ALEX" and row.type == "SKIN":
            result["metadata"] = {
                "model": "silm"
            }
        return result

    def profile(self, row: model.Profile, options: dict = {}):
        self.options.update(options)
        result = {
            "id": row.uuid.hex,
            "name": row.name
        }

        if self.options.hasProperties:
            textures = {}
            if row.skin:
                textures["skin"] = self.resource(model.Resource.get(model.Resource.uuid == row.skin))
            if row.cape:
                textures["cape"] = self.resource(model.Resource.get(model.Resource.uuid == row.cape))
            result["properties"] = [
                {
                    "name": "textures",
                    "value": Base64(str({
                        "timestamp": timestamp_now(),
                        "profileId": row.uuid.hex,
                        "profileName": row.charId,
                        "textures": textures
                    }).encode()).decode("utf-8")
                }
            ]
            if not self.options.unsigned:
                for i in range(len(result['properties'])):
                    result['properties'][i]['signature'] = self._sign_text(result['properties'][i]['value'])

        return result