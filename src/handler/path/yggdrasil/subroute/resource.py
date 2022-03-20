from entrancebar import entrance_file, path_render, entrance_package
import os.path
import tornado.web

Route = entrance_package("router").Route
Model = entrance_file("@/database/model.py")
Manager = entrance_file("@/database/connector.py").Manager
ImageResponse = entrance_file("@/common/Respond.py").ImageResponse
Response = entrance_file("@/common/Respond.py").Response

@Route.add(r"/resources/(?P<name>.*)")
async def resource_get(self, name):
    path = path_render("${projectDir}/data/resources/{name}.png").format(name=name)
    return (
        ImageResponse(open(path, "rb").read())
        if os.path.exists(path)
        else Response(status=404)
    )