import model
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
        return False
    return token.get("group") == group_id