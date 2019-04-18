import json
import utils
from flask import Flask
import cacheout
import searchcache

config = utils.Dict2Object(json.loads(open("./data/config.json").read()))
raw_config = json.loads(open("./data/config.json").read())
app = Flask(__name__)
cache = cacheout.Cache(ttl=0)
Token = searchcache.TokenCache(cache)
