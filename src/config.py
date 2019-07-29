__import__('sys').path.append(__import__("os").path.dirname(__import__("os").path.realpath(__file__)) + "/..")
# Config Parser
import etc as Config
ConfigObject = Config.GetConfigObject()
ConfigDict = Config.GetConfigDict()