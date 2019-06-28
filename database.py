import peewee
import json
from base import config

db = {}
db['global'] = peewee.__dict__[config.database.type](config.database.connect_info.global_db, **config.database.globalinfo)
db['global'].connect()
db['log'] = peewee.SqliteDatabase("data/tmp.db:foobar_database?mode=memory&cache=shared")
db['log'].connect()