import asyncio
import os
import logging

from tornado.web import Application
import tornado.ioloop
import tornado.log
import peewee_async
from entrancebar import entrance_file, path_render

from routes import Route
from config import ConfigObject
import sys
from common.FormsDict import FormsDict

ImportedModules = {
    path_render(ConfigObject.EnabledModules.__getattr__(i)): {
        "module": entrance_file(ConfigObject.EnabledModules.__getattr__(i)),
        "name": i
    } for i in ConfigObject.EnabledModules
}

def ModuleConfig():
    if sys._getframe(1).f_code.co_filename not in ImportedModules:
        return None
    return ConfigObject.ModulesConfig[ImportedModules[sys._getframe(1).f_code.co_filename]["name"]]

GlobalApp = Application(Route.load())
print(Route.routes)
import database.connector
import database.model
GlobalApp.objects = FormsDict({
    "Database": database.connector.Manager,
    "ModuleConfig": ModuleConfig
})

existed_tables = database.connector.SelectedDatabase.get_tables()
print("框架中已注册的数据表(已进行处理): " + ", ".join([i.__name__.lower() for i in database.model.BaseModel.__subclasses__()]))
print("数据库中现有的数据表: " + ", ".join(existed_tables))

for i in database.model.BaseModel.__subclasses__():
    if i.__name__.lower() not in existed_tables:
        i.create_table()

tornado.log.enable_pretty_logging()

if __name__ == "__main__":
    GlobalApp.listen(ConfigObject.Serve.Port)
    print("serve on http://{0}:{1}".format("0.0.0.0", ConfigObject.Serve.Port))
    tornado.ioloop.IOLoop.current().start()