from base import config, app, Token, cache_head
from flask import request, Response, redirect, url_for, send_file
import json
import uuid
import model
import utils
import os

@app.route("/texture/<image>", methods=['GET'])
def imageview(image):
    return Response(open(os.getcwd() + "/data/texture/" + image + '.png', "rb"), mimetype='image/png')

@app.route("/texture/<image>/head", methods=['GET'])
def imageview_head(image):
    try:
        if cache_head.get(image):
            return Response(cache_head.get(image), mimetype='image/png')
        filename = "".join([os.getcwd(), "/data/texture/", image, '.png'])
        texture = model.gettexture_hash(utils.PngBinHash(filename))
        if not texture:
            return Response(json.dumps(dict(
                error="Not Found",
                errorMessage="无法找到相应文件."
                )), status=404, mimetype='application/json; charset=utf-8')
        if texture.type != "SKIN":
            return Response(json.dumps(dict(
                error="皮肤请求类型错误",
                errorMessage="无法抓取该类型皮肤文件的head部分",
            )), status=403, mimetype='application/json; charset=utf-8')
        img = utils.gethead_skin(filename)
        cache_head.set(image, img)
    except FileNotFoundError:
        return Response(status=404)
    return Response(img, mimetype='image/png')

@app.route("/texture/textureid/<image>/head", methods=['GET'])
def imageview_head_textureid(image):
    try:
        texture = model.gettexture(image)
        if not texture:
            return Response(json.dumps(dict(
                error="Not Found",
                errorMessage="无法找到相应文件."
                )), status=404, mimetype='application/json; charset=utf-8')
        if cache_head.get(texture.hash):
            return Response(cache_head.get(image), mimetype='image/png')
        filename = "".join([os.getcwd(), "/data/texture/", texture.hash, '.png'])
        if texture.type != "SKIN":
            return Response(json.dumps(dict(
                error="皮肤请求类型错误",
                errorMessage="无法抓取该类型皮肤文件的head部分",
            )), status=403, mimetype='application/json; charset=utf-8')
        img = utils.gethead_skin(filename)
        cache_head.set(image, img)
    except FileNotFoundError:
        return Response(status=404)
    return Response(img, mimetype='image/png')