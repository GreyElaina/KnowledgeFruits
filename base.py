import json
import utils
from flask import Flask, Response
import cacheout
import time
import model
import Exceptions
import werkzeug.exceptions
class TokenCache():
    def __init__(self, CacheObject):
        self.CacheObject = CacheObject

    def _format(self, string):
        return string

    def getuser_byaccessToken(self, accessToken):
        result = self.CacheObject.get(self._format(accessToken))
        if not result:
            return False
        return model.getuser_uuid(result)
    
    def getalltoken(self, User):
        result = []
        for i in self.CacheObject:
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


cache_token = cacheout.Cache(ttl=0, maxsize=8192)
cache_limit = cacheout.Cache(ttl=0, maxsize=22)
cache_joinserver = cacheout.Cache(ttl=0, maxsize=128)
cache_secureauth = cacheout.Cache(ttl=0, maxsize=8192)
cache_uploadtoken = cacheout.Cache(ttl=0, maxsize=256)
cache_head = cacheout.Cache(ttl=0, maxsize=32768)

Token = TokenCache(cache_token)
# For someone
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# for error
@app.errorhandler(Exception)
def errorhandler(error):
    if error.__class__ in Exceptions.__dict__.values():
        return Response(json.dumps({
            "error": error.error,
            "errorMessage": error.message
        }), status=error.code, mimetype='application/json; charset=utf-8')
    else:
        raise error
"""
@app.errorhandler(werkzeug.exceptions.HTTPException)
def errorhandler_natura(error):
    return Response(error.description, status=error.code)"""