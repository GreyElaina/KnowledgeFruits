from entrancebar import entrance_file, path_render, entrance_package
from tornado.web import RequestHandler
from datetime import datetime, timedelta

from cacheout import Cache
from uuid import UUID

Route = entrance_package("router").Route
model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
FormsDict = entrance_file("@/common/FormsDict.py").FormsDict
password = entrance_file("@/common/cryptor.py")
importext = entrance_file("@/common/importext/__init__.py")
Exceptions = entrance_file("../Exceptions.py")
query = entrance_file("@/database/query.py")
config = entrance_file("@/common/config.py").ConfigObject
DataFormat = entrance_file("../common/data.py").Format
json = importext.AlternativeImport("ujson", "json")

Respond = entrance_file("@/common/Respond.py")
JSONResponse = Respond.JSONResponse
Response = Respond.Response

tokens = entrance_package("token").tokens

authlimit = Cache()

@Route.add("/api/yggdrasil/authserver/authenticate", Method="post", restful=True)
async def ygg_authserver_authenticate(self: RequestHandler):
    data = self.json
    try:
        user = await manager.get(query.account_email(data.get("username")))
    except model.User.DoesNotExist:
        raise Exceptions.InvalidCredentials()

    if not authlimit.get(".".join(['lock', user.email])):
        authlimit.set(".".join(['lock', user.email]), "LOCKED", ttl=1)
    else:
        raise Exceptions.InvalidCredentials()

    if password.saltcat(data.get("password"), user.salt) != user.password:
        raise Exceptions.InvalidCredentials()
    Format = DataFormat(self.request)
    profiles_query = query.profiles_userid(user.uuid)
    profiles = await manager.execute(profiles_query)
    # profiles.count() == 1
    unit = tokens.newToken(
        datetime.now(),
        datetime.now() + timedelta(**config.TokenManage.Refreshline),
        datetime.now() + timedelta(**config.TokenManage.Deadline),
        user=user.uuid, clientToken=data.get("clientToken"),
        profile=(await manager.get(profiles_query)).uuid if await manager.count(profiles_query) == 1 else None
    )
    result = {
        "accessToken": unit.accessToken.hex,
        "clientToken": str(unit.clientToken),
        "availableProfiles": [
            Format.profile(i, {"unsigned": True, "hasProperties": False}) for i in profiles
        ],
        "selectedProfile": {}
    }
    if unit.profile.uuid:
        result["selectedProfile"] = Format.profile(await manager.get(query.profile_uuid(unit.profile.uuid)), {"unsigned": True})
    else:
        del result['selectedProfile']

    if data.get("requestUser"):
        result["user"] = {
            "id": user.uuid.hex,
            "properties" : []
        }
    return JSONResponse(result)

@Route.add("/api/yggdrasil/authserver/refresh", Method="post", restful=True)
async def ygg_authserver_refresh(self):
    data = self.json
    original = tokens.get(data.get("accessToken"), data.get("clientToken"))

    if not original:
        raise Exceptions.InvalidToken()

    if not tokens.validate_disabled(data.get("accessToken"), data.get("clientToken")):
        raise Exceptions.InvalidToken()

    user = await manager.get(query.account_uuid(original.account.uuid))
    selected_profile = None
    if original.profile.uuid:
        selected_profile = await manager.get(query.profile_uuid(original.profile.uuid.hex))
    if data.get("selectedProfile"):
        if selected_profile: # Token已绑定一已知角色
            raise Exceptions.IllegalArgumentException()

        try:
            attempt_select = await manager.get(query.profile_name_uuid({
                "uuid": data.get("selectedProfile").get("id"),
                "name": data.get("selectedProfile").get("name")
            })) # 尝试将角色绑定到Token上
        except model.Profile.DoesNotExist: # 角色不存在
            raise Exceptions.IllegalArgumentException()
        
        if attempt_select.owner != user.uuid: # 该已知角色不属于该用户
            raise Exceptions.WrongBind()
        selected_profile = attempt_select # 确认绑定

    tokens.delete(data.get("accessToken"))

    unit = tokens.newToken(
        datetime.now(),
        datetime.now() + timedelta(**config.TokenManage.Refreshline),
        datetime.now() + timedelta(**config.TokenManage.Deadline),
        user=user.uuid, clientToken=original.clientToken,
        profile=selected_profile.uuid if selected_profile else None
    )

    result = {
        "accessToken": unit.accessToken.hex,
        "clientToken": str(unit.clientToken)
    }
    Format = DataFormat(self.request)
    if selected_profile:
        result['selectedProfile'] = Format.profile(selected_profile, {"unsigned": True})

    if data.get("requestUser"):
        result["user"] = {
            "id": user.uuid.hex,
            "properties" : []
        }
    
    return JSONResponse(result)

@Route.add("/api/yggdrasil/authserver/validate", Method="post", restful=True)
async def ygg_authserver_validate(self):
    data = self.json
    original = tokens.get(data.get("accessToken"), data.get("clientToken"))
    if not original:
        raise Exceptions.InvalidToken()

    if not tokens.validate(original.accessToken):
        return Response(status=204)
    else:
        raise Exceptions.InvalidToken()

@Route.add("/api/yggdrasil/authserver/invalidate", Method="post", restful=True)
async def ygg_authserver_invalidate(self):
    data = self.json
    original = tokens.get(data.get("accessToken"), data.get("clientToken"))
    if original:
        tokens.delete(data.get("accessToken"))
    elif data.get("clientToken"):
        original = tokens.get(data.get("accessToken"))
        if original:
            tokens.delete(data.get("accessToken"))
        else:
            raise Exceptions.InvalidToken()
    else:
        return Response(status=204)
    return Response(status=204)

@Route.add("/api/yggdrasil/authserver/signout", Method="post", restful=True)
async def ygg_authserver_signout(self):
    data = self.json
    try:
        user = await manager.get(query.account_email(data.get("username")))
    except model.User.DoesNotExist:
        raise Exceptions.InvalidCredentials()

    if not authlimit.get(".".join(['lock', user.email])):
        authlimit.set(".".join(['lock', user.email]), "LOCKED", ttl=1)
    else:
        raise Exceptions.InvalidCredentials()

    if password.saltcat(data.get("password"), user.salt) != user.password:
        raise Exceptions.InvalidCredentials()
    for i in tokens.getManyToken(user.uuid.hex):
        tokens.delete(i.accessToken.hex)
        tokens.TokenIndex.delete(i.clientToken.hex)
    return Response(status=204)