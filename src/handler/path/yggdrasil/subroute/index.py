from routes import Route
from Respond import JSONResponse, Response
from entrancebar import entrance_file, path_render
from urllib.parse import parse_qs, urlencode, urlparse
from functools import reduce

from uuid import UUID

model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
importext = entrance_file("@/common/importext/__init__.py")
FormsDict = entrance_file("@/common/FormsDict.py").FormsDict
Exceptions = entrance_file("../Exceptions.py")
databox = entrance_file("../common/data.py")
config = entrance_file("@/config.py").ConfigObject
DataFormat = databox.Format
Resource = entrance_file("../resource.py")
json = importext.AlternativeImport("ujson", "json")

@Route.add("/api/yggdrasil/")
async def ygg_index(self):
    config = self.application.objects.ModuleConfig()
    return JSONResponse({
        "meta": config['IndexData'],
        "skinDomains": [[urlparse(self.request.full_url()).netloc.split(":")[0]], config.get("SiteDomain")]["SiteDomain" in config],
        "signaturePublickey": open(path_render(config['SignnatureKeys']["Public"]), "r").read()
    })

@Route.add(r"/api/yggdrasil/sessionserver/session/minecraft/profile/(?P<profile>.*)", Method="get")
async def ygg_sessionserver_query_profile(self, profile):
    args = self.request.arguments
    try:
        result = await manager.get(databox.profile_uuid(profile))
    except model.Profile.DoesNotExist:
        return Response(status=204)
    Format = DataFormat(self.request)
    return JSONResponse(Format.profile(result, {
        "unsigned": {"false": False, "true": True, None: True}[args.get('unsigned')],
        "hasProperties": True,
        "enableSmartDecide": True
    }))

@Route.add("/api/yggdrasil/api/profiles/minecraft", Method="post", restful=True)
async def ygg_api_query_profiles(self):
    data = reduce(lambda x,y:x if y in x else x + [y], [[], ] + self.json)
    result = []
    Format = DataFormat(self.request)
    for i in range(FormsDict(self.application.objects.ModuleConfig()).Profile.QueryLimit - 1):
        try:
            result.append(
                Format.profile(await manager.get(databox.profile_name(data[i])), {
                    "unsigned": True
                })
            )
        except model.Profile.DoesNotExist:
            continue
        except IndexError:
            pass
    return JSONResponse(result)