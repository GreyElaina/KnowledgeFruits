from cacheout import (Cache, CacheManager)
import uuid
import datetime

GlobalCacheCore: CacheManager = CacheManager()

class TokenError(Exception): pass

class Context(object):
    def __init__(self, **kwargs):
        for i in kwargs.keys():
            setattr(self, i, kwargs[i])

class Token(Cache):
    def newToken(
        self,
        start: datetime.datetime, refrush: datetime.datetime, end: datetime.datetime, 
        user: uuid.UUID, clientToken=None, group=None, profile: uuid.UUID = None
    ):
        accessToken = uuid.uuid4()
        if not clientToken:
            clientToken = uuid.uuid1()

        Unit = Context(
            accessToken=accessToken,
            clientToken=clientToken,
            established=Context(
                start=start,
                refrush=refrush,
                deadline=end
            ),
            account=Context(
                uuid=user,
                group=group
            ),
            profile=Context(
                uuid=profile
            )
        )
        self.set(accessToken.hex, Unit, ttl=(end - start).seconds)
        return Unit

    def get(self, accessToken, clientToken=None):
        result = super().get(accessToken)
        if clientToken and result and result.clientToken != clientToken:
            return
        return result

    def getManyToken(self, userId):
        return [i for i in self.values() if i.account.uuid.hex == userId]

    def validate(self, accessToken, clientToken=None):
        """
        True为未过期, False为已过期, 该接口表示Token是否可以正常使用
        """
        result = self.get(accessToken, clientToken)
        if not result:
            return False
        return datetime.datetime.now() <= result.established.refrush

    def validate_disabled(self, accessToken, clientToken=None):
        """
        True为未过期, False为已过期, 该接口表示Token是否可以正常刷新
        """
        result = self.get(accessToken, clientToken)
        if not result:
            return False
        return datetime.datetime.now() <= result.established.deadline

tokens = Token()