from entrancebar import entrance_file
import peewee
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

def texture_userid(uuid):
    return model.Resource.select().where(model.Resource.owner == uuid)

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

def account_many(options):
    original = {
        "email": None,
        "userid": None
    }
    for i in original.keys():
        original[i] = options.get(i)
    
    original = {k: v for k, v in original.items() if v}

    if not original:
        return

    wheres = [model.User.__dict__[k].field == v for k, v in original.items()]
    context = wheres[0]
    for i in wheres[1:]:
        context = context.bin_and(i)

    return model.User.select().where(context)