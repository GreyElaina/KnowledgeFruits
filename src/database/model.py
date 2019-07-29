
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

