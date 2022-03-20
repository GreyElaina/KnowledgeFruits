from entrancebar import entrance_file, path_render
from urllib.parse import urlunparse, ParseResult
from base64 import b64encode as Base64
from time import time as timestamp_now
import rsa

model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
FormsDict = entrance_file("@/common/FormsDict.py").FormsDict
Config = entrance_file("@/common/config.py").ConfigObject
importext = entrance_file("@/common/importext/__init__.py")

json = importext.AlternativeImport("ujson", "json")

class Format:
    options = FormsDict({
        "unsigned": True,
        "hasProperties": False,
        "hasMetadata": True,
        "enableSmartDecide": False
    })
    def _sign_text(self, data, key_file=path_render(Config.ModulesConfig.yggdrasil.SignnatureKeys.Private)):
        key_file = open(key_file, 'r').read()
        key = rsa.PrivateKey.load_pkcs1(key_file.encode('utf-8'))
        return bytes(Base64(rsa.sign(data.encode("utf-8"), key, 'SHA-1'))).decode("utf-8")

    def __init__(self, request):
        self.request = request

    def resource(self, row: model.Resource):
        result = {
            "url": urlunparse(ParseResult(
                scheme=self.request.protocol,
                netloc=self.request.host,
                path="/resources/{0}".format(row.hash),
                params="",
                query="",
                fragment=""
            ))
        }
        if self.options.enableSmartDecide and row.model == "ALEX" and row.type == "SKIN":
            result["metadata"] = {
                "model": "slim"
            }
        if self.options.hasMetadata and row.type == "SKIN":
            result["metadata"] = {
                "model": {"STEVE": 'default', "ALEX": 'slim'}[row.model]
            }
        return result

    def profile(self, row: model.Profile, options: dict = {}):
        self.options.update(options)
        result = {
            "id": row.uuid.hex,
            "name": row.name
        }

        if self.options.hasProperties or not self.options.unsigned:
            textures = {}
            if row.skin:
                textures["SKIN"] = self.resource(model.Resource.get(model.Resource.uuid == row.skin))
            if row.cape:
                textures["CAPE"] = self.resource(model.Resource.get(model.Resource.uuid == row.cape))
            result["properties"] = [
                {
                    "name": "textures",
                    "value": Base64(json.dumps({
                        "timestamp": int(round(timestamp_now())),
                        "profileId": row.uuid.hex,
                        "profileName": row.name,
                        "textures": textures
                    }).encode("utf-8")).decode("utf-8")
                }
            ]
        if not self.options.unsigned:
            for i in range(len(result['properties'])):
                result['properties'][i]['signature'] = self._sign_text(result['properties'][i]['value'])

        return result