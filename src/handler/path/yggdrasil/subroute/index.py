from entrancebar import entrance_file, path_render, entrance_package
from urllib.parse import parse_qs, urlencode, urlparse
from functools import reduce

from uuid import UUID

Route = entrance_package("router").Route
model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
importext = entrance_file("@/common/importext/__init__.py")
FormsDict = entrance_file("@/common/FormsDict.py").FormsDict
Exceptions = entrance_file("../Exceptions.py")
query = entrance_file("@/database/query.py")
config = entrance_file("@/common/config.py").ConfigObject
DataFormat = entrance_file("../common/data.py").Format
json = importext.AlternativeImport("ujson", "json")

Respond = entrance_file("@/common/Respond.py")
JSONResponse = Respond.JSONResponse
Response = Respond.Response

@Route.add("/api/yggdrasil/")
async def ygg_index(self):
    config = self.application.objects.ModuleConfig.get()
    return JSONResponse({
        "meta": config['IndexData'],
        "skinDomains": [[urlparse(self.request.full_url()).netloc.split(":")[0]], config.get("SiteDomain")]["SiteDomain" in config],
        "signaturePublickey": open(path_render(config['SignnatureKeys']["Public"]), "r").read()
    })

@Route.add("/api/yggdrasil/api/profiles/minecraft", Method="post", restful=True)
async def ygg_api_query_profiles(self):
    data = reduce(lambda x,y:x if y in x else x + [y], [[], ] + self.json)
    result = []
    Format = DataFormat(self.request)
    for i in range(FormsDict(self.application.objects.ModuleConfig.get()).Profile.QueryLimit - 1):
        try:
            result.append(
                Format.profile(await manager.get(query.profile_name(data[i])), {
                    "unsigned": True
                })
            )
        except model.Profile.DoesNotExist:
            continue
        except IndexError:
            pass
    return JSONResponse(result)