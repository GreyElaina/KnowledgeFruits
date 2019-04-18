import peewee
import json
import utils as base

config = base.Dict2Object(json.loads(open("./data/config.json").read()))

db = {}
db['global'] = peewee.__dict__[config.database.type](config.database.connect_info.global_db, **config.database.globalinfo)
db['global'].connect()
