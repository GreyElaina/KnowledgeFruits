import json
import utils
from flask import Flask, Response
import cacheout
import time
import model
class TokenCache():
    def __init__(self, CacheObject):
        self.CacheObject = CacheObject

    def _format(self, string):
        return ".".join(["token", string])

    def getuser_byaccessToken(self, accessToken):
        result = self.CacheObject.get(self._format(accessToken))
        if not result:
            return False
        return model.getuser_uuid(result)
    
    def getalltoken(self, User):
        result = []
        for i in self.CacheObject:
            if not i[:5] == "token":
                continue
            if self.CacheObject.get(i).get("user") == User.uuid:
                result.append(i)
        return result

    def is_validate_strict(self, AccessToken, ClientToken=None):
        if not ClientToken:
            result = self.CacheObject.get(self._format(AccessToken))
        else:
            result = self.CacheObject.get(self._format(AccessToken))
            if not result:
                return False
            if not result.get("clientToken") == ClientToken:
                return False
        if not result:
            return False
        return int(time.time()) >= result.get("createTime") + (config.TokenTime.EnableTime * config.TokenTime.TimeRange)

    def is_validate(self, AccessToken, ClientToken=None):
        result = self.CacheObject.get(self._format(AccessToken))
        if not result:
            return False
        return int(time.time()) >= result.get("createTime") + (config.TokenTime.EnableTime * config.TokenTime.TimeRange)
 
    def gettoken(self, AccessToken, ClientToken=None):
        result = self.CacheObject.get(self._format(AccessToken))
        if not result:
            return False
        return result
    
    def gettoken_strict(self, AccessToken, ClientToken=None):
        if not ClientToken:
            result = self.CacheObject.get(self._format(AccessToken))
        else:
            result = self.CacheObject.get(self._format(AccessToken))
            if not result:
                return False
            if not result.get("clientToken") == ClientToken:
                return False
        if not result:
            return False
        return result

config = utils.Dict2Object(__import__("json").loads(open("./data/config.json").read()))
raw_config = json.loads(open("./data/config.json").read())
app = Flask("main")
cache = cacheout.Cache(ttl=0, maxsize=32768)
Token = TokenCache(cache)

# For someone
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 

# for error
@app.errorhandler(Exception)
def errorhandler(error):
    return Response(json.dumps({
        "error": error.error,
        "errorMessage": error.message
    }), status=403, mimetype='application/json; charset=utf-8')