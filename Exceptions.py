class InvalidRequestData(Exception):
    error = "ForbiddenOperationException"
    message = "Invalid request data."
    code = 403

class InvalidToken(Exception):
    error = "ForbiddenOperationException"
    message = "Invalid token."
    code = 403

class InvalidCredentials(Exception):
    error = "ForbiddenOperationException"
    message = "Invalid credentials. Invalid username or password."
    code = 403

class IllegalArgumentException(Exception):
    error = "IllegalArgumentException"
    message = "Access token already has a profile assigned."
    code = 400
    
class DuplicateData(Exception):
    error = "ForbiddenOperationException"
    message = "Duplicate data."
    code = 403

ErrorList = [InvalidCredentials, InvalidRequestData, InvalidToken, IllegalArgumentException, DuplicateData]