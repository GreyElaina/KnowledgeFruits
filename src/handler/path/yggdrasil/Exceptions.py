class BaseException(Exception):
    NoAnyMoreConfiure = False
    def __init__(self, error=None, errorMessage=None, code=None, message="SomethingWrong"):
        if not self.NoAnyMoreConfiure:
            self.error = error
            self.message = errorMessage,
            self.code = code
        super().__init__(message)


class InvalidRequestData(BaseException):
    NoAnyMoreConfiure = True
    error = "ForbiddenOperationException"
    message = "Invalid request data."
    code = 403

class WrongBind(BaseException):
    NoAnyMoreConfiure = True
    error = "ForbiddenOperationException"
    message = "Attempting to bind a token to a role that does not belong to its corresponding user."
    code = 403

class InvalidToken(BaseException):
    NoAnyMoreConfiure = True
    error = "ForbiddenOperationException"
    message = "Invalid token."
    code = 403

class InvalidCredentials(BaseException):
    NoAnyMoreConfiure = True
    error = "ForbiddenOperationException"
    message = "Invalid credentials. Invalid username or password."
    code = 403

class IllegalArgumentException(BaseException):
    NoAnyMoreConfiure = True
    error = "IllegalArgumentException"
    message = "Access token already has a profile assigned."
    code = 400
    
class DuplicateData(BaseException):
    NoAnyMoreConfiure = True
    error = "ForbiddenOperationException"
    message = "Duplicate data."
    code = 403

# for errorHandler
from entrancebar import entrance_file
errorHandler = entrance_file("@handler/error/__init__.py").errorHandler
AlternativeImport = entrance_file("@/common/importext/__init__.py").AlternativeImport
json = AlternativeImport("ujson", "json")

@errorHandler(*(BaseException.__subclasses__() + [BaseException]))
def __ygg_errorhandler(sender, data):
    error = data.Exception
    rh = data.RequestHandler
    rh.clear()
    rh.set_status(error.code)
    rh.set_header("Content-type", "application/json; charset=UTF-8")
    rh.write(json.dumps({
        "error": error.error,
        "errorMessage": error.message
    }))
