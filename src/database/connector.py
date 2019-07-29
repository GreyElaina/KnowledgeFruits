import os
import sys
from entrancebar import entrance_file

config = entrance_file("../config.py")
FormsDict = entrance_file("../common/FormsDict.py").FormsDict
import peewee
import peewee_async

ConnectInfo = FormsDict(config.ConfigObject.Database[config.ConfigObject.Database.Use])

SelectedDatabase = peewee_async.PooledPostgresqlDatabase(
    ConnectInfo.Database,
    host=ConnectInfo.Host,
    port=ConnectInfo.Port,
    user=ConnectInfo.Username,
    password=ConnectInfo.Password
)
Manager = peewee_async.Manager(SelectedDatabase)