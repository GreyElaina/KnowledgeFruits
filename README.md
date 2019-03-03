# Knowledge Fruits(智慧果)
使用Python驱动的Mojang Yggdrasil服务端, 旨在开箱即用而不失功能.

# Running
确认Python版本 `>= 3.6.0`, 并使用pip安装扩展:

```
python3 -m pip install -r requirements.text
```
或:
```
python3 -m pip install rsa flask peewee flask_limiter simplejson flask_apscheduler pyopenssl scikit-image scipy numpy
```

运行main.py即启动:
```
python3 main.py
```

确保运行目录下有 `data`, `data/texture` 目录.

# 配置
本程序所有配置都在 `config.py` 文件内.  
本说明只包含你可以更改的配置项, 其他最好别改.  
配置项说明:


|配置名称|配置说明|默认值|备注|
|:-|:-:|:-:|:-:|
|`const`|配置大部分文本型常量|||
|`const.debug`|网页调试路由地址|`/debug`|该路由下默认只配置了 `test` 接口|
|`const.base`|`Yggdrasil API`根目录, 即`Api Root`|`/api/yggdrasil`|举个例子, 如果你要访问 `/authserver/refresh` 接口, 默认情况下你就要访问`/api/yggdrasil/authserver/refresh`, 这个配置项是最重要的.如果你想把服务部署在 `/` , 你可以把该项留空|
|`ServerName`|服务名称|`KnowledgeFruits - Minecrart Yggdrasil`||
|`database`|数据库配置|||
|`database.type`|数据库类型|`sqlite`|使用其他数据库需要自己写支持|
|`database.connect_info`|数据库连接Key||你可以将各项的值改为你想连接的数据库的`绝对路径或相对路径.`|
|`database.globalinfo`|在连接每个数据库时所传入的其他参数||你可以在该项内填入`host`, `user`, `password`等等, 也可以改`charset`.|
|`dbtype`|对各类数据库的支持配置|||
|`limiter_filter`|请求速率限制||使用`flask_limiter`的语法|
|`limiter_filter.default_limits`|默认赋值给各路由的速率限制||使用`flask_limiter`的语法|
|`NeedF5`|使登录令牌状态为`需要刷新`可持续的时间, 单位天|5|实际上,登录令牌状态为`需要刷新`可持续的时间默认是`CanUse - NeedF5`天, 当`NeedF5`为5, `CanUse`为3时, 用户只有第4,5天,共计`2`天可以执行刷新操作|
|`CanUse`|登录令牌状态为`正常`持续的时间, 单位天|3||
|`runattr`|app.run函数启动时传入的参数|||
|`runattr.host`|服务监听的地址|`0.0.0.0`||
|`runattr.port`|服务监听的端口|`5001`||
|`runattr.debug`|调试模式, 在生产环境中用时请设为`False`|`True`||
|**`url`**|服务实际访问地址|`http://192.168.31.189:5001`|实际设置时请**不要**让最后有个`/`, 会死人的.|
|`SiteDomain`|允许的皮肤文件来源||填入你的域名或者IP,不带端口那种|
