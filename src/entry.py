import asyncio
import logging
import os
import sys

import peewee_async
import tornado.ioloop
import tornado.log
from tornado.web import Application
import ssl
from tornado.web import HTTPServer

import database.connector
import database.model
from common.FormsDict import FormsDict
from entrancebar import entrance_file, entrance_package, path_render

Route = entrance_package("router").Route
config = entrance_file("@/common/config.py")
ConfigObject = config.ConfigObject
Modules = config.ModuleConfig()

ImportedModules = {
    path_render(Modules.config[i]["__name__"]): {
        "module": entrance_file(Modules.config[i]["entry"]),
        "name": i
    } for i in Modules.config.keys()
}
GlobalApp = Application(Route.load())
GlobalApp.objects = FormsDict({
    "Database": database.connector.Manager,
    "ModuleConfig": Modules
})

existed_tables = database.connector.SelectedDatabase.get_tables()
print(f'框架中已注册的数据表(已进行处理): {", ".join([i.__name__.lower() for i in database.model.BaseModel.__subclasses__()])}')
print(f'数据库中现有的数据表: {", ".join(existed_tables)}')

for i in database.model.BaseModel.__subclasses__():
    if i.__name__.lower() not in existed_tables:
        i.create_table()

tornado.log.enable_pretty_logging()

if __name__ == "__main__":
    GlobalApp.listen(ConfigObject.Serve.Port)
    print("serve on http://{0}:{1}".format("0.0.0.0", ConfigObject.Serve.Port))
    tornado.ioloop.IOLoop.current().start()
