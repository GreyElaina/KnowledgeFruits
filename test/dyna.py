import tornado.web

# 跳转到前端显示页面
class txtPathHandler(tornado.web.RequestHandler):
    def get(self, path):
        self.render(path)

# 逻辑处理
class indexHandler(tornado.web.RequestHandler):  # 定义一个类，继承tornado.web下RequestHandler类
    def get(self,num,nid):  # get()方法，接收get方式请求
        print(num,nid)

app=tornado.web.Application(
    handlers=[
        (r"/(?P<path>\w*.txt)",txtPathHandler),# 判断请求路径是否匹配字符串.txt,如果匹配执行txtPathHandler方法
        (r"/index/(?P<num>\d*)/(?P<nid>\d*)", indexHandler)# 判断请求路径是否匹配字符串index,如果匹配执行MainHandler方法
    ]
)

app.listen(8082)
tornado.ioloop.IOLoop.current().start()