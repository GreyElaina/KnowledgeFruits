import model

def GetUserToken(User):
    return model.db_token.select().where(model.db_token.createby == User.email)

def ChangeToken_AsOuttimed(Token):
    Token.status = 1
    Token.save()

def ChangeToken_AsDisabled(Token):
    Token.status = 2
    Token.save()

def VerivyToken_isExists(AccessToken):
    try:
        model.db_token.get(accessToken=AccessToken)
    except Exception as e:
        if "db_tokenDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        return True

def VerivyToken_isEnabled(AccessToken):
    try:
        result = model.db_token.get(accessToken=AccessToken)
    except Exception as e:
        if "db_tokenDoesNotExist" == e.__class__.__name__:
            return False
        raise e
    else:
        if result.status == 0:
            return True
        else:
            return False

def VerivyToken_isDisabled(AccessToken):
    return not VerivyToken_isEnabled(AccessToken)