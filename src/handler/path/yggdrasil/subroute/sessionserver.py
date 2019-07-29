from routes import Route
from Respond import JSONResponse, Response
from entrancebar import entrance_file, path_render

from cacheout import Cache
from uuid import UUID

model = entrance_file("@/database/model.py")
manager = entrance_file("@/database/connector.py").Manager
importext = entrance_file("@/common/importext/__init__.py")
Exceptions = entrance_file("../Exceptions.py")
databox = entrance_file("../common/data.py")
config = entrance_file("@/config.py").ConfigObject
DataFormat = databox.Format
Resource = entrance_file("../resource.py")
json = importext.AlternativeImport("ujson", "json")

tokens = entrance_file("../util.py").tokens

@Route.add("/api/yggdrasil/sessionserver/session/minecraft/join", Method="post", restful=True)
async def ygg_sessionserver_join(self):
    data = self.json
    tokens.validate(data.get("accessToken"), data.get("clientToken"))