from entrancebar import entrance_file

# 大骆峰用于命名面向逻辑层的数据调用抽象接口
# pep8的命名标准用于基础库,但要用上lib_的前缀
# 至于框架内的玩意..原来怎么样就怎么样

lib_security = entrance_file("./security.py")

Query = entrance_file('@/database/query.py')
Manager = entrance_file("@/database/connector.py")

Route = entrance_file("@/routes/__init__.py")

@Route.add("/api/prometheus/authenticate/security/signin", Method="post", restful=True)
async def prometheus_authenticate_security_signin(self):
    '''获取登录用的登录ID

    通过一已知用户的email(已验证), 获取一登录ID, 存于本地缓存中以进行安全登录.

    请求示例:
        {
            "client": "tad54ha54tawg56w5tb",
            "user": {
                "email": "user1@to2mbn.org",
                "userId": "0ff8df779b35411da8835e4584c8b270"
            }
        }

    响应示例:
        {
            "id": "tad54ha54tawg56w5tb", // 这里是请求中的"client"字段的内容
            "salt": "13456hsdar" // 数据库中用户的salt....好吧这不是什么安全的方法,我得想想..
        }

    '''
    data = self.json
    lib_security.randomString(8)
    token_client = data.get("client")