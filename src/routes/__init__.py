from Respond import BaseResponse, JSONResponse

from tornado.web import RequestHandler
from entrancebar import entrance_file
from blinker import signal
import traceback
ConfigObject = entrance_file("@/config.py").ConfigObject
AlternativeImport = entrance_file("@/common/importext/__init__.py").AlternativeImport

FormsDict = entrance_file("@/common/FormsDict.py").FormsDict

json = AlternativeImport("ujson", "json")

class RequestCat(RequestHandler):
    @property
    def is_json(self):
        try:
            json.loads(self.request.body.decode())
        except json.decoder.JSONDecodeError if json.__name__ == "json" else ValueError:
            return False
        return True

    @property
    def json(self):
        return json.loads(self.request.body.decode())

class RepeatedException(Exception): pass

class Routes:
    routes = {}

    def _add(self, Route):
        def warpper(Handler):
            self.routes[Route] = Handler
            return Handler
        return warpper

    def add(self, Route, Method: str = "get", force=False, restful=False):
        def warpper(Handler):
            method = Method.lower()
            assert method in set(["get", "post", "head", "delete", "patch", "put", "options"])

            async def HandlerMixin(self, **kwargs):
                if restful and method == "post":
                    if not self.is_json:
                        JSONResponse({
                            "error": "ForbiddenOperationException",
                            "errorMessage": "The submitted data is not in the correct format."
                        }, status=403).render(self)
                try:
                    ReturnResponse = await Handler(self, **kwargs)
                except Exception as e:
                    if bool(signal(e.__class__).receivers):
                        signal(e.__class__).send("HandlerMixin", data=FormsDict({
                            "Exception": e,
                            "RequestHandler": self,
                            "Handler": Handler
                        }))
                    else:
                        raise e
                else:
                    ReturnResponse.render(self)

            if self.routes.setdefault(Route, {}):
                if method in self.routes[Route]:
                    if not force:
                        raise RepeatedException("Do not add the same route repeatedly.")
            self.routes[Route][method] = HandlerMixin
            return Handler
        return warpper
    
    def load(self):
        return [(i, type(str(hash(i)), (RequestCat,), self.routes[i])) for i in self.routes.keys()]

Route = Routes()