from entrancebar import entrance_file, entrance_package
from datetime import timedelta, datetime
import uuid

# 大骆峰用于命名面向逻辑层的数据调用抽象接口
# pep8的命名标准用于基础库,但要用上lib_的前缀
# 至于框架内的玩意..原来怎么样就怎么样

lib_security = entrance_file("./security.py")

Query = entrance_package('query')
Responses = entrance_package("responses")
Manager = entrance_file("@/database/connector.py").Manager
Token = entrance_package("token").tokens
Exceptions = entrance_file("../exceptions")
Model = entrance_package("model")
Config = entrance_package("config").ConfigObject
SaltCat = entrance_package("cryptor").saltcat
NotFound = Model.NotFound

Route = entrance_file("@/routes").Route

JSONResponse = Responses.JSONResponse
Response = Responses.Response

@Route.add("/api/prometheus/authenticate/signin", Method="post", restful=True)
async def prometheus_authenticate_signin(self):
    '''获取登录用的登录ID

    用户登录用的API, 另外, 强制使用https.

    请求示例:
        {
            "client": "tad54ha54tawg56w5tb", // 即clientToken, 可以是任何字符串.
            "user": {
                "email": "user1@to2mbn.org", // email和userId两个都可以用, 但要对.
                "userId": "0ff8df779b35411da8835e4584c8b270",
                "password": "111111" // 明文密码, 强制https的用途
            },
            "request": {
                "profiles": {
                    "limit": 2,
                    "strict": true // 当该请求返回空时提交错误.
                }
            }
        }

    响应示例:
        {
            "client": "tad54ha54tawg56w5tb", // 这里是请求中的"client"字段的内容
            "accesstoken": "", // 随机字符串, 通常是一UUID4.
            "user": {
                "userId": "0ff8df779b35411da8835e4584c8b270"
            },
            "response": {
                // 然后就根据你要求搞了一堆玩意来....
                "profiles": {
                    ...
                }
            }
        }

    有可能抛出的错误(~~虽然全部都被捕获了...~~):
        Exceptions.IllegalAccessProtocol
        Exceptions.VerificationFailed
        Exceptions.IllegalRequestPatameters
        Exceptions.EmptyData

    '''
    if self.request.protocol != "https" and not Config.debug:
        raise Exceptions.IllegalAccessProtocol()
    data = self.json

    if not data.get("user"): # 先看看到底有没有需要验证的这玩意...
        raise Exceptions.VerificationFailed(addon={"position": "request.body.user"})
    
    try:
        user = await Manager.get(Query.account_many(data['user']))
    except NotFound(Model.User):
        raise Exceptions.VerificationFailed(addon={"position": "request.body.user"})

    if not data['user'].get("password"):
        raise Exceptions.VerificationFailed(addon={"position": "request.body.user.password", "exist": False})
    
    if not SaltCat(data['user']['password'], user.salt) == user.password:
        raise Exceptions.VerificationFailed(addon={
            "position": "request.body.user.password",
            "validated": False
        })
    
    unit = Token.newToken(
        datetime.now(),
        datetime.now() + timedelta(**Config.TokenManage.Refreshline),
        datetime.now() + timedelta(**Config.TokenManage.Deadline),
        user=user.uuid, clientToken=data.get("client")
    )
    response = None
    if data.get("request"):
        # 请求特殊数据.
        class DataPolymerization:
            @staticmethod
            async def profiles(request: dict):
                query = Query.profiles_userid(user.uuid)
                if request.get("limit"):
                    if isinstance(request['limit'], int):
                        query = query.limit(request.get("limit"))
                    else:
                        raise Exceptions.IllegalRequestPatameters()
                result = await Manager.execute(query)
                if not result and request.get("strict"):
                    raise Exceptions.EmptyData()
                return [{
                    "uuid": i.uuid.hex,
                    "player": {
                        "name": i.name,
                        "uuid": i.charId.hex
                    },
                    "textures": {
                        "skin": i.skin.hex if i.skin else None,
                        "cape": i.cape.hex if i.cape else None
                    }
                } for i in result]

            @staticmethod
            async def textures(request):
                query = Query.texture_userid(user.uuid)
                if request.get("limit"):
                    if isinstance(request['limit'], int):
                        query = query.limit(request.get("limit"))
                    else:
                        raise Exceptions.IllegalRequestPatameters()
                result = await Manager.execute(query)
                if not result and request.get("strict"):
                    raise Exceptions.EmptyData()
                return [{
                    "uuid": i.uuid.hex,
                    "type": i.type,
                    "name": i.name,
                    "size": i.size,
                    "model": i.model,
                    "hash": i.hash,
                } for i in result]
                
        response = {i: await getattr(DataPolymerization(), i)(data['request'][i]) for i in data['request'].keys() if hasattr(DataPolymerization(), i)}
    return JSONResponse(dict({
        "accesstoken": unit.accessToken.hex,
        "client": unit.clientToken.hex if isinstance(unit.clientToken, uuid.UUID) else unit.clientToken,
        "user": {
            "uuid": user.uuid.hex
        }
    }, **(response if response else {})))