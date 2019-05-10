class InvalidRequestData(Exception):
    error = "ForbiddenOperationException"
    message = "Invalid request data."

class InvalidToken(Exception):
    error = "ForbiddenOperationException"
    message = "Invalid token."

class InvalidCredentials(Exception):
    error = "ForbiddenOperationException",
    errorMessage = "Invalid credentials. Invalid username or password."