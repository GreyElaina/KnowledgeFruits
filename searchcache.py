import cacheout
import model
import time
from database import config

class TokenCache():
    def __init__(self, CacheObject):
        self.CacheObject = CacheObject

    def _format(self, string):
        return ".".join(["token", string])

    def getuser_byaccessToken(self, accessToken):
        result = self.CacheObject.get(self._format(accessToken))
        if not result:
            return False
        return model.user.get(model.user.email == result['user'])
    
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
        return int(time.time()) >= result.get("createTime") + config.TokenTime.EnableTime

    def is_validate(self, AccessToken, ClientToken=None):
        result = self.CacheObject.get(self._format(AccessToken))
        if not result:
            return False
        return int(time.time()) >= result.get("createTime") + config.TokenTime.EnableTime
 
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