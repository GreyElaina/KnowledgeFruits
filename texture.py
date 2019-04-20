from base import config, cache, app, Token
from flask import request, Response, redirect, url_for
import json
import uuid
import model
import utils
import os

@app.route("/texture/<image>", methods=['GET'])
def imageview(image):
    try:
        with open(os.getcwd() + "/data/texture/" + image + '.png', "rb") as f:
            image = f.read()
    except FileNotFoundError:
        return Response(status=404)
    return Response(image, mimetype='image/png')

@app.route("/texture/<image>/head", methods=['GET'])
def imageview_head(image):
    try:
        filename = "".join([os.getcwd(), "/data/texture/", image, '.png'])
        texture = model.gettexture_hash(utils.PngBinHash(filename))
        if not texture:
            return redirect(url_for('service_error',
                error="Not Found",
                errorMessage="无法找到相应文件.",
                status=404)
            )
        if texture.type != "SKIN":
            return Response(json.dumps(dict(
                error="皮肤请求类型错误",
                errorMessage="无法抓取该类型皮肤文件的head部分",
            )), status=403)
        image = utils.gethead_skin(filename)
    except FileNotFoundError:
        return Response(status=404)
    return Response(image, mimetype='image/png')