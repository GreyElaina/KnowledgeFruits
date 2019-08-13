from entrancebar import entrance_file
model = entrance_file("@/database/model.py")

# 下划线前是要获取的信息,下划线后是需要给出的信息(多个信息用options代替)
# 这里全部返回Query, 由逻辑处运算并查找信息.

def account_email(email):
    return model.User.select().where(model.User.email == email)

def profiles_userid(userid):
    return model.Profile.select().where(model.Profile.owner == userid)

def account_uuid(uuid):
    return model.User.select().where(model.User.uuid == uuid)

def profile_uuid(uuid):
    return model.Profile.select().where(model.Profile.uuid == uuid)

def profile_name(name):
    return model.Profile.select().where(model.Profile.name == name)

def profile_name_uuid(options):
    original = {
        "uuid": None,
        "name": None
    }
    original.update(options)
    if not any(original):
        return False
    return model.Profile.select().where(
        (model.Profile.uuid == options.get("uuid")) & 
        (model.Profile.name == options.get("name"))
    )