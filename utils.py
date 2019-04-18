import hashlib
import binascii
import random
from io import BytesIO
#from skimage import io
from PIL import Image
import datetime
import time

def gettimestamp(date):
    #return int(time.mktime(date.timetuple()))
    return int(date)

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

def factorial(n):
    result = n
    for i in range(1, n):
        result *= i
    return result

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

def dec2hex(num):
    base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]
    l = []
    if num < 0:
        return '-' + dec2hex(abs(num))
    while True:
        num,rem = divmod(num, 16)
        l.append(base[rem])
        if num == 0:
            return ''.join(l[::-1])

def PngBinHash(SkinPath):
    photo = Image.open(SkinPath)
    width, height = photo.size
    #return photo.getpixel((4, 4))
    with BytesIO() as Buf:
        #Buf.write(struct.pack(">I", width))
        #Buf.write(struct.pack(">I", height))
        Buf.write(width.to_bytes(4, "big"))
        Buf.write(height.to_bytes(4, "big"))
        for w in range(width):
            for h in range(height):
                data = list(photo.getpixel((w, h)))
                Buf.write(data[3].to_bytes(1, "big"))
                if data[3] == 0:
                    Buf.write((0).to_bytes(1, "big"))
                    Buf.write((0).to_bytes(1, "big"))
                    Buf.write((0).to_bytes(1, "big"))
                else:
                    Buf.write(data[0].to_bytes(1, "big"))
                    Buf.write(data[1].to_bytes(1, "big"))
                    Buf.write(data[2].to_bytes(1, "big"))
        return hashlib.sha256(Buf.getvalue()).hexdigest()

def getblock(skin, block=(1, 1)):
    photo = Image.open(skin)
    photo = photo.crop((block[0]*8, block[1]*8, (block[0]+1)*8, (block[1]+1)*8))
    #with open("./faq.png", 'wb') as f:
    #imgByteArr = BytesIO()
    #photo.save(imgByteArr, format='PNG')
    return photo

def gethead_skin(skin):
    rawhead = getblock(skin)
    rawheat = getblock(skin, block=(5, 1))
    rawhead.paste(rawheat, (0, 0), rawheat.split()[3])
    imgByteArr = BytesIO()
    rawhead.save(imgByteArr, format='PNG')
    return imgByteArr.getvalue()

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
    #print(PngBinHash("./data/texture/212d8dfa3695daba43b406851c00105a2669d9681a44aa1e109a88ddf324f576.png"))
    #print(r"0x00".encode("utf-8"))8e364d6d4886a76623062feed4690c67a23a66c5d84f126bd895b903ea26dbee.png
    #print(PngBinHash("./data/texture/texture-hash-test.png"))
    #import time
    #time_start = time.time()
    #with open("./faq.png", "wb") as f:
    #    f.write(gethead_skin("./data/texture/81c26f889ba6ed12f97efbac639802812c687b4ffcc88ea75d6a8d077328b3bf.png"))
    #time_end = time.time()
    #print('totally cost',time_end-time_start)
    #print(PngBinHash("./data/texture/74349566b05e0d4db0705fe511851e119341538575648c369d9dd6fcf8c8623e.png"))
    pass