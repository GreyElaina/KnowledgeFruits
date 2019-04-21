from base import config, cache, app, Token
from flask import request, Response
import json
import uuid
import model
import hashlib
from PIL import Image, ImageDraw
import utils

SizeConfig = config.UploadSkin.security.size

@app.route("/api/fairy/security/checkinfo", methods=["POST"])
def fairy_checkinfo():
    if request.is_json:
        data = request.json
        sha256 = data.get("sha256", 0)
        size = data.get("size", 0)
        name = data.get("name", 0)
        accessToken = data.get("accessToken", 0)
        if False in [size, sha256, accessToken, name]:
            return Response(json.dumps({
                "error": "ForbiddenOperationException",
                "errorMessage": "Invalid Data"
            }))
        else:
            if not Token.gettoken_strict(accessToken):
                return Response(json.dumps({
                    "error": "ForbiddenOperationException",
                    "errorMessage": "Invalid Token."
                }))
            if Token.is_validate_strict(accessToken):
                return Response(json.dumps({
                    "error": "ForbiddenOperationException",
                    "errorMessage": "Invalid Token."
                }))
            if model.gettexture_photoname(name):
                return Response(json.dumps({
                    "error": "ForbiddenOperationException",
                    "errorMessage": "Invalid Data."
                }))
            UploadToken = str(uuid.uuid4()).replace("-", "")
            if False in [
                SizeConfig.height[0] < size.get("height") < SizeConfig.height[1],
                SizeConfig.width[0] < size.get("width") < SizeConfig.width[1]
            ]:
                return Response(json.dumps({
                    "error": "PictureDecodeError",
                    "errorMessage": "Invalid Size."
                }), status=403, mimetype='application/json; charset=utf-8')
            cache.set(".".join(["fairy", "security", "checkinfo", UploadToken]), {
                "sha256": sha256,
                "size": size,
                "accessToken": accessToken,
                "name": name
            }, ttl=30)
            # size:
            # height
            # width
            return Response(json.dumps({"uploadToken": UploadToken}))

@app.route("/api/fairy/security/upload", methods=['POST'])
def fairy_upload():
    data = request.data
    header = data[:(32 + 64)].decode()
    Cached = cache.get(".".join(["fairy", "security", "checkinfo", header[:32]]))
    if not Cached:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "Invalid Token."
        }), status=403, mimetype='application/json; charset=utf-8')
    imagehex = header[32:]
    if model.gettexture_hash(imagehex):
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "Quantum repeatability does not hold here."
        }), status=403, mimetype='application/json; charset=utf-8')
    hexed = hashlib.sha256(data[(32 + 64):]).hexdigest()
    if Cached.get("sha256") != hexed:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "Hash value does not match."
        }), status=403, mimetype='application/json; charset=utf-8')
    size = Cached.get("size")
    height = size.get("height")
    width = size.get("width")
    if len(data) - (32 + 64) < ((height * width) * 4):
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "Parsing does not provide sufficient amount of bytes"
        }), status=403, mimetype='application/json; charset=utf-8')
    if (len(data) - (32 + 64)) % 4 != 0:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "No correct encoded image."
        }), status=403, mimetype='application/json; charset=utf-8')
    
    if not ((height % 32 == 0) or (height % 17 == 0)) and ((width % 64 == 0) or (width % 22 == 0)):
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "No correct encoded image."
        }), status=403, mimetype='application/json; charset=utf-8')
    
    if not (height % 17 != 0):
        height = int(width / 17) * 32
    
    if not (width % 22 != 0):
        width = int(width / 22) * 32

    image = Image.new('RGBA', (width, height), (255, 255, 255, 255))
    draw = ImageDraw.Draw(image)
    dots = utils.chunk(list(data[(32 + 64):]), 4)[2:]
    chunks = utils.chunk(dots, height)
    for x in range(len(chunks)):
        for y in range(len(chunks[x])):
            draw.point((x, y), fill=(chunks[x][y][1], chunks[x][y][2], chunks[x][y][3], chunks[x][y][0]))
    image.save("".join(["./data/texture/", imagehex, ".png"]), "PNG")
    
    #开始判断皮肤类型
    if len(list(set(list(utils.getblock_PIL(image).getdata())))) == 1:
        skintype = "SKIN"
    else:
        skintype = "CAPE"
    
    if skintype == "SKIN":
        if height % 64 == 0:
            if len(list(set(list(image.crop((width - 2, height - 12, width, height)).getdata())))) == 1 and list(set(list(image.crop((width - 2, height - 12, width, height)).getdata()))) == (255, 255, 255 ,255):
                skinmodel = "ALEX"
            else:
                skinmodel = "STEVE"
    texture = model.textures(
        userid=Token.gettoken_strict(Cached.get("accessToken")).get("user"),
        photoname=Cached.get("name"),
        height=height,
        width=width,
        model=skinmodel,
        type=skintype,
        hash=hexed
    )
    texture.save()
    return Response(model.kf_format_textures(texture), mimetype='application/json; charset=utf-8')
    #for y in range(len(chunks)):
    #    for x in range(len(y)):
    #        draw.point((x, y), fill=(chunks[y][x][1], chunks[y][x][2], chunks[y][x][3], chunks[y][x][0]))
    #image.show()