from routes import Route
from entrancebar import entrance_file, path_render
from tornado.web import RequestHandler

from cacheout import Cache
from uuid import UUID

model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
importext = entrance_file("@/common/importext/__init__.py")
Exceptions = entrance_file("../Exceptions.py")
query = entrance_file("@/database/query.py")
config = entrance_file("@/common/config.py").ConfigObject
DataFormat = entrance_file("../common/data.py").Format
Resource = entrance_file("../resource.py")
json = importext.AlternativeImport("ujson", "json")

Respond = entrance_file("@/common/Respond.py")
JSONResponse = Respond.JSONResponse
Response = Respond.Response

tokens = entrance_file("@handler/token/main.py").tokens

ServerJoin = Cache()

@Route.add("/api/yggdrasil/sessionserver/session/minecraft/join", Method="post", restful=True)
async def ygg_sessionserver_join(self):
    data = self.json
    if tokens.validate(data.get("accessToken")):
        token = tokens.get(data.get("accessToken"))
        if not token:
            raise Exceptions.InvalidToken()
        if not token.profile.uuid:
            raise Exceptions.InvalidToken()
        try:
            result = await manager.get(query.profile_uuid(token.profile.uuid))
        except model.Profile.DoesNotExist:
            raise Exceptions.InvalidToken()
        player = await manager.get(query.profile_name(result.name))
        if data.get("selectedProfile") == player.uuid.hex:
            ServerJoin.set(data.get("serverId"), {
                "token": token,
                "profile": player,
                "remoteIp": self.request.remote_ip
            }, ttl=30)
            return Response(status=204)
        else:
            raise Exceptions.InvalidToken()
    else:
        raise Exceptions.InvalidToken()

@Route.add("/api/yggdrasil/sessionserver/session/minecraft/hasJoined")
async def ygg_sessionserver_checkjoin(self: RequestHandler):
    serverId = self.get_argument("serverId")
    playerName = self.get_argument("username")
    remoteIp = self.get_argument("ip", None)
    cachedData = ServerJoin.get(serverId)
    if not cachedData:
        return Response(status=204)
    if all([
        playerName == cachedData['profile'].name,
        remoteIp == cachedData['remoteIp'] if remoteIp else True
    ]):
        Format = DataFormat(self.request)
        return JSONResponse(Format.profile(cachedData['profile'], {
            "hasProperties": False,
            "enableSmartDecide": True,
            "unsigned": False
        }))
    else:
        return Response(status=204)


@Route.add(r"/api/yggdrasil/sessionserver/session/minecraft/profile/(?P<profile>.*)", Method="get")
async def ygg_sessionserver_query_profile(self, profile):
    try:
        result = await manager.get(query.profile_uuid(profile))
    except model.Profile.DoesNotExist:
        return Response(status=204)
    Format = DataFormat(self.request)
    return JSONResponse(Format.profile(result, {
        "unsigned": {"false": False, "true": True}[self.get_argument("unsigned", "true")],
        "hasProperties": True,
        "enableSmartDecide": True,
        "hasMetadata": False
    }))