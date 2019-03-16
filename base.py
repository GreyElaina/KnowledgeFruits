import hashlib
import binascii
import random
from io import BytesIO
from skimage import io
import struct

def hex2bin(hexstring):
    #return ''.join([chr(int(b, 16)) for b in [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]])
    al = []
    for i in range(0, len(hexstring), 2):
        b = hexstring[i:i+2]
        al.append(chr(int(b, 16)))
    return ''.join(al)

def bin2hex(sendbin):
    e = 0
    for i in sendbin:
      d = ord(i)
      e = e * 256 + d
    return hex(e)[2:]

def md5(string):
    return hashlib.md5(string.encode(encoding='utf-8')).hexdigest()

def substr(string, start, length=None):
    return string[start if start >= 0 else 0:][:length if length != None else len(string) - start]

def OfflinePlayerUUID(name):
    data = list(hex2bin(md5("OfflinePlayer:" + name)))
    data[6] = chr(ord(data[6]) & 0x0f | 0x30)
    data[8] = chr(ord(data[8]) & 0x3f | 0x80)
    def getuuid(string):
        components = [
            substr(str(string), 0, 8),
            substr(str(string), 8, 4),
            substr(str(string), 12, 4),
            substr(str(string), 16, 4),
            substr(str(string), 20),
        ]
        return "-".join(components)
    return getuuid(bin2hex("".join(data)))

def pad8(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def CreateSalt(length=32):
    chars = r"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890~`_-+=|\{}[]:;'<,>.?/!@#$%^&*()"
    IReturn = ""
    while len(IReturn) != 32:
        IReturn += chars[random.randint(0, len(chars) - 1)]
    return IReturn

def PngBinHash(SkinPath):
    Image = io.imread(SkinPath)
    Height = Image.shape[0]
    Width = Image.shape[1]
    with BytesIO() as Buf:
        Buf.write(struct.pack(">i", Width))
        Buf.write(struct.pack(">i", Height))
        for w in range(Width):
            for h in range(Height):
                dot = Image[h][w]
                ImageInfo = {
                    'R' : dot[0],
                    'G' : dot[1],
                    'B' : dot[2],
                    'A' : dot[3],
                }
                if ImageInfo['A'] == 0:
                    Buf.write(bytes([0]))
                    Buf.write(bytes([0]))
                    Buf.write(bytes([0]))
                    Buf.write(bytes([0]))
                else:
                    Buf.write(ImageInfo['A'])
                    Buf.write(ImageInfo['R'])
                    Buf.write(ImageInfo['G'])
                    Buf.write(ImageInfo['B'])

        return hashlib.sha256(Buf.getvalue()).hexdigest()

class Dict(dict):
    __setattr__ = dict.__setitem__
    __getattr__ = dict.__getitem__
 
def Dict2Object(Object):
    if not isinstance(Object, dict):
        return Object
    inst=Dict()
    for k,v in Object.items():
        inst[k] = Dict2Object(v)
    return inst

def StitchExpression(Object):
    return "".join([Object.content, "{%s,%s}" % (Object.length.min, Object.length.max), "$" if Object.isSigner else ""])

if __name__ == "__main__":
    #print(PngBinHash("./data/texture/1cd0db978f11733c4d6480fff46dd3530518e82eee23eb1ecb568550a35553ad.png") == '8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee')
    #print(r"0x00".encode("utf-8"))8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee.png
    pass