import model
from base import Token
import Exceptions

def is_exist_group(group_id):
    return bool(model.group.select().where(model.group.id == group_id))

def isingroup(user_id, group_id):
    return bool(model.member.select().where((model.member.group == group_id) & (model.member.user == user_id) & (model.member.is_disabled == False)))

def has_permission_in_group(user_id, group_id):
    if not isingroup(user_id, group_id):
        return False
    return model.member.select().where(
        (model.member.is_disabled == False) &
        (model.member.group == group_id) &
        (model.member.user == user_id)
    ).get().permission in ['manager', "super_manager"]

def token_is_group(token, group_id):
    if not isingroup(token.get("user"), group_id):
        raise Exceptions.InvalidToken()
    return token.get("group") == group_id

def auto_verify(request):
    data = request.json
    accessToken = data.get("accessToken")
    clientToken = data.get("clientToken")
    if not accessToken:
        raise Exceptions.InvalidToken()
    if Token.is_validate_strict(accessToken, clientToken):
        raise Exceptions.InvalidToken()
    return Token.gettoken_strict(accessToken, clientToken)

def get_member(group_id, user_id):
    result = model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == user_id) &
        (model.member.is_disabled == False)
    )
    if not result:
        raise Exceptions.InvalidToken()
    return result

def get_group(group_id):
    result = model.group.select().where(model.group.id == group_id)
    if not result:
        raise Exceptions.InvalidToken()
    return result.get()

def isManager(group_id, user_id):
    result = get_member(group_id, user_id).get()
    if result.permission not in ['manager', 'super_manager']:
        raise Exceptions.InvalidToken()
    return result

def autodata(request):
    if not request.is_json:
        raise Exceptions.InvalidRequestData()
    return request.json

def is_super_manager(group_id, user_id):
    return isManager(group_id, user_id).permission == "super_manager"

def get_member_common_user(group_id, user_id):
    result = get_member(group_id, user_id).get()
    if result.permission != "common_user":
        raise Exceptions.InvalidToken()
    return result