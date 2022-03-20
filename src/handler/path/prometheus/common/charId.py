import hashlib

def hex2bin(hexstring):
    al = [chr(int(hexstring[i:i+2], 16)) for i in range(0, len(hexstring), 2)]
    return ''.join(al)

def bin2hex(sendbin):
    e = 0
    for i in sendbin:
        e = e * 256 + ord(i)
    return hex(e)[2:]

def md5(string):
    return hashlib.md5(string.encode(encoding='utf-8')).hexdigest()

def substr(string, start, length=None):
    return string[max(start, 0) :][
        : (length if length is not None else (len(string) - start))
    ]

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