
from peewee import (Model, BooleanField, CharField, UUIDField, TimestampField, TextField)
# from database.connector import SelectedDatabase
from entrancebar import entrance_file
SelectedDatabase = entrance_file("./connector.py").SelectedDatabase
from playhouse.fields import PickledField
from peewee_async import Manager
from playhouse.kv import JSONField

import uuid

class BaseModel(Model):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.trans = SelectedDatabase.atomic_async
        # self.object = Manager(SelectedDatabase)

    class Meta:
        database = SelectedDatabase

class User(BaseModel):
    uuid = UUIDField(unique=True, index=True, default=uuid.uuid4)
    name = CharField(null=True)
    head = UUIDField(null=True)
    email = CharField(unique=True, index=True)
    password = CharField()
    salt = CharField()
    permission = CharField(default="CommonUser")
    # 权限分这么几个:
    # 1.CommonUser -- 就是一般通过的普通用户
    # 2.Manager -- 具有对用户进行受限操作, 对部分敏感数据(日志)进行调取的权限, 也就是op
    # 3.Owner -- 一个实例中只有一个, 也就是服主/站长/The Administrator/Cat, 
    #            具有对所有数据(仅可修改, 且不影响实例整体的数据)进行
    #            调取/修改/新增/删除的权限(但是没办法触碰到基本设施的配置)
    registerTime = TimestampField(utc=True)

class Profile(BaseModel):
    uuid = UUIDField(unique=True, index=True, default=uuid.uuid4)
    name = CharField()
    charId = UUIDField(unique=True, index=True)
    skin = UUIDField(index=True, default=None, null=True)
    cape = UUIDField(index=True, default=None, null=True)

    createTime = TimestampField(utc=True)
    owner = UUIDField(index=True)

class Resource(BaseModel):
    uuid = UUIDField(unique=True, index=True, default=uuid.uuid4)
    type = CharField()
    named = BooleanField(default=False)
    name = CharField(null=True)
    size = JSONField(default={"size": {"height": 64, "width": 32}})
    model = CharField(default="STEVE")
    hash = TextField()
    privated = BooleanField(default=False)
    owner = UUIDField()

