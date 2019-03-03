from os import getcwd
import random
import peewee

# 常量部分
const = {
    "cwd" : getcwd(),
    "__name__" : __name__,
    'base' : "/api/yggdrasil",
    'debug' : "/debug"
}

ServerName = "KnowledgeFruits - Minecrart Yggdrasil"

# 数据库
database = {
    "type": "sqlite",
    "connect_info": {
        "global" : const['cwd'] + "/data/global.db",
        "cache" : const['cwd'] + "/data/cache.db"
    },
    'globalinfo': {}
}

# Peewee用
dbtype = {
    "sqlite": {
        "class": peewee.SqliteDatabase,
        "attrs": ['database'],
        "templates": lambda: database['globalinfo'],
        "attr": {
            "database" : {
                i : lambda: database['connect_info'][i] for i in database['connect_info'].keys()
            }
        }
    }
}

# 访问速率限制相关(flask-limiter)
limiter_filter = {
    'whitelist' : [],
    'default_limits' : ["30/minute,1/second"]
}

# loginToken过期的限界划分(三个阶段),单位:天
NeedF5 = 5 # 在该区段内,用户必须使用启动器登录,通常,启动器已经完成该操作.如果超过这些日子你就必须重新登录了.
CanUse = 3 # 在该区段内,用户成功登录后,默认3天不用输入密码登录
TimeRange = 86400 # 时间区间,通常不需要去动
'''TokenOutTime = {
    'canUse' : lambda time: time <= (86400 * CanUse),
    'needF5' : lambda time: time > TokenOutTime['canUse'] and time <= 86400 * NeedF5 # 
}'''
TokenOutTime = {
    'canUse' : lambda time: time <= (TimeRange * CanUse),
    'needF5' : lambda time: time <= (TimeRange * NeedF5) and time >= (TimeRange * CanUse)
}

# 没啥卵用的salt
salt = r'sX*h}b<.$&$vt8mzgS%9IE6nXe3EU|=`'

# app.run()函数运行参数
runattr = {
    "debug" : True,
    'host' : '0.0.0.0',
}

# texture目录
texturepath = const['cwd'] + "/data/texture/"

# 实际访问地址
url = 'http://192.168.31.189:5000/'

# Token清道夫程序 执行间隔,单位 分
ChangeTokenStatus = 1
ClearTokenMinute = 2

# MemSqlite过期数据清理程序设置
Outtime = 30
RunMinute_Change = 30
RunMinute_Delete = 60

# /api/profiles/minecraft接口最大查找数
MaxSearch = 5

IndexMeta = {
    'serverName' : ServerName,
    'implementationName' : "knowledge_fruits",
    'implementationVersion' : 'v0.0.1'
}

SiteDomain = [
    '192.168.31.189'
]

RSAPEM = './data/rsa.pem'
PUBLICKEY = './data/public.pem'