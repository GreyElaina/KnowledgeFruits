import requests
import hashlib
from io import BytesIO
from PIL import Image

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

authenticate = requests.post("http://127.0.0.1:5001/api/yggdrasil/authserver/authenticate", json={
    "username": "test3@to2mbn.org",
    "password": "dct"
})
print(authenticate.text)
AuthInfo = {
    "accessToken": authenticate.json().get("accessToken"),
    "clientToken": authenticate.json().get("clientToken")
}
fairy_gettoken = requests.post("http://127.0.0.1:5001/api/fairy/security/checkinfo", json={
    "sha256": PngBinHash("./steve.png"),
    "size": {
        "height": 32,
        "width": 64
    },
    "accessToken": AuthInfo['accessToken'],
    "name": "steve"
}).json()
print(fairy_gettoken)
UploadToken = fairy_gettoken.get("uploadToken")
photo = Image.open("./steve.png")
width, height = photo.size
C = ""
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
    C = Buf.getvalue()
upload = requests.post("http://127.0.0.1:5001/api/fairy/security/upload", UploadToken.encode() + PngBinHash("./steve.png").encode() + C)
print(len(upload.json()))