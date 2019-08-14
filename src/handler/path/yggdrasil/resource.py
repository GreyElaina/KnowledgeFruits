from entrancebar import entrance_file, path_render
import os.path
from routes import Route
import tornado.web

Model = entrance_file("@/database/model.py")
Manager = entrance_file("@/database/connector.py").Manager
ImageResponse = entrance_file("@/common/Respond.py").ImageResponse
Response = entrance_file("@/common/Respond.py").Response

@Route.add(r"/resources/(?P<name>.*)")
async def resource_get(self, name):
    path = path_render("${projectDir}/data/resources/{name}.png").format(name=name)
    if not os.path.exists(path):
        return Response(status=404)
    else:
        return ImageResponse(open(path, "rb").read())