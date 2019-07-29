import os
import json

__import__('sys').path.append(os.path.dirname(os.path.realpath(__file__)) + "/..")

import src.common.FormsDict

def GetConfigDict():
    return json.load(open(os.path.dirname(os.path.realpath(__file__)) + "/core.json"))

def GetConfigObject():
    return src.common.FormsDict.FormsDict(GetConfigDict())

if __name__ == "__main__":
    print(GetConfigObject().Database.Use)
