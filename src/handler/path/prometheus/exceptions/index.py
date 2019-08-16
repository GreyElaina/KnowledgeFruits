class base(Exception):
    nac = False # NoAnymoreConfigure
    def __init__(self, error=None, message=None, code=None, addon={}, RaiseMessage="SomethingWrong"):
        if not self.nac:
            self.error = error
            self.message = message
            self.code = code
            self.addon = addon
        super().__init__(RaiseMessage)

    def updateAddon(self, obj):
        self.addon = obj
        return self

# 这里写点 关于错误 的表述方式吧:
#   UnsatisfiedRequirements - 可取得的数据不符合用户请求需求, 也可以形容无法取得但实际存在的数据.
#
#   IllegalRequestMethod - 用户的请求中(指HTTP请求的配置部分而不是传递信息主体)具有不被接受的部分,
#                          这部分数据通常会在附加数据中被指出, 并通常以
#                                "Part of the data request is not accepted."
#                          作为message.
#
#   

class EmptyData(base):
    nac = True
    error = "UnsatisfiedRequirements",
    message = "Actual data is Unsatisfied for the request condition."
    code = 403

class IllegalAccessProtocol(base):
    nac = True
    error = "IllegalRequestMethod"
    message = "Part of the data request is not accepted."
    code = 403
    addon = {
        "position": "request.protocol"
    }

class VerificationFailed(base):
    nac = True
    error = "VerificationFailed"
    message = "Unable to process the information submitted in the request."
    code = 403

class IllegalRequestPatameters(base):
    nac = True
    error = "IllegalRequestParameters"
    message = "An incoming parameter definition type error was found while parsing the parameters of the extra request."
    code = 403

from entrancebar import entrance_file
errorHandler = entrance_file("@handler/error").errorHandler
AlternativeImport = entrance_file("@/common/importext").AlternativeImport
json = AlternativeImport("ujson", "json")

@errorHandler(*(base.__subclasses__() + [base]))
def __ygg_errorhandler(sender, data):
    error = data.Exception
    rh = data.RequestHandler
    rh.clear()
    rh.set_status(error.code)
    rh.set_header("Content-type", "application/json; charset=UTF-8")
    result = {
        "error": error.error,
        "message": error.message
    }
    if error.addon:
        result['addon'] = error.addon
    rh.write(json.dumps(result))