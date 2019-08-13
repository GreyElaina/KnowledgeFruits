__import__('sys').path.append(__import__("os").path.dirname(__import__("os").path.realpath(__file__)) + "/..")
# Config Parser
import etc as Config
ConfigObject = Config.GetConfigObject()
ConfigDict = Config.GetConfigDict()

from mako.template import Template
from entrancebar import path_render, add_path
import sys
import os.path

class ModuleConfig:
    def __init__(self):
        self.config = {}
        for i in ConfigDict['EnabledModules'].keys():
            # 现在开始解析每一个模块的配置
            if isinstance(ConfigDict['EnabledModules'][i], str):
                self.config[i] = {
                    "singleFile": True,
                    "dir": {"enable": False},
                    "entry": path_render(ConfigDict['EnabledModules'][i]),
                    "__name__": i
                }
            elif isinstance(ConfigDict['EnabledModules'][i], dict):
                self.config[i] = {
                    "singleFile": True,
                    "dir": {"enable": False},
                    "entry": "",
                    "__name__": i
                }
                self.config[i].update(ConfigDict['EnabledModules'][i])
                if self.config[i]['dir']['enable']:
                    self.config[i]['dir']['value'] = path_render(self.config[i]['dir']['value'])
                    self.config[i]['entry'] = Template(self.config[i]['entry']).render(dir=self.config[i]['dir']['value'])
                self.config[i]['entry'] = path_render(self.config[i]['entry'])

    def get(self):
        for i in self.config.keys():
            #print(i, self.config[i], os.path.dirname(os.path.abspath(sys._getframe(1).f_code.co_filename)))
            if self.config[i]['dir']['enable']:
                if self.config[i]['dir']['value'].replace("\\", "/") in os.path.dirname(os.path.abspath(sys._getframe(1).f_code.co_filename)).replace("\\", "/"):
                    return ConfigDict['ModulesConfig'].get(i)