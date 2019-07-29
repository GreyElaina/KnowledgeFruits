from routes import Route
from Respond import JSONResponse
from entrancebar import entrance_file

User = entrance_file("@/database/model.py").User
Base = entrance_file("@/database/model.py").BaseModel

@Route.add(r"/flaskic")
@Route.add(r"/flaskic", Method="post")
async def hello(self):
    try:
        await self.application.objects.get(User, email="1846913566@qq.com")
    except User.DoesNotExist:
        return JSONResponse({
            "error": "FAQ!!!!"
        })
    return JSONResponse({
        "HaveFUN": True
    })

@Route.add("/debug2", Method="post")
async def helloworld(self):
    return str(self.request.__dict__)