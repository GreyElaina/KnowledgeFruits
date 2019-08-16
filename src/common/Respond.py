from entrancebar import entrance_file
AlternativeImport = entrance_file("@/common/importext/__init__.py").AlternativeImport
json = AlternativeImport("ujson", "json")

class BaseResponse:
    def __init__(self, body="", status=200):
        self.body = body
        self.status = status

class Response(BaseResponse):
    def __init__(self, body="", status=200, mimetype=""):
        self.body = body
        self.status = status
        self.minetype = ""

    def render(self, request):
        request.set_status(self.status)
        request.set_header("Content-type", self.minetype)
        if self.status != 204:
            request.write(self.body)

class JSONResponse(BaseResponse):
    def render(self, request):
        request.set_status = self.status
        request.set_header("Content-type", "application/json; charset=UTF-8")
        print(self.body)
        request.write(json.dumps(self.body))

class ImageResponse(BaseResponse):
    def render(self, request):
        request.set_status(self.status)
        request.set_header("Content-type", "image/png")
        request.write(self.body)