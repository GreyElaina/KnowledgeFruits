import peewee
import json
import utils as base

_config = base.Dict2Object(json.loads(open("./data/config.json").read()))

db = {}
db['global'] = peewee.__dict__[_config.database.type](_config.database.connect_info.global_db, **_config.database.globalinfo)
db['global'].connect()
db['log'] = peewee.SqliteDatabase("file:foobar_database?mode=memory&cache=shared")
db['log'].connect()