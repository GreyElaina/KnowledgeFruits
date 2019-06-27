from base import config, app, Token
from flask import request, Response
import json
import uuid
import model
import hashlib
import utils
import os

def format_profile_csl(profile):
    IReturn = {
        "username": profile.name,
        "textures": {}
    }
    if profile.skin:
        skin = model.gettexture(profile.skin)
        if skin:
            model.gettexture(profile.skin)
            IReturn['textures'][{"STEVE": "default", "ALEX": "silm"}[skin.model]] = skin.hash

    if profile.cape:
        cape = model.gettexture(profile.cape)
        if cape:
            model.gettexture(profile.skin)
            IReturn['textures']["cape"] = cape.hash

    return IReturn

@app.route("/api/customskin/<profile>.json")
def customskin(profile):
    profile = model.getprofile(profile)
    if not profile:
        return Response(status=404)
    return Response(json.dumps(format_profile_csl(profile)), mimetype='application/json; charset=utf-8')

@app.route("/api/customskin/textures/<image>", methods=['GET'])
def csl_imageview(image):
    try:
        with open(os.getcwd() + "/data/texture/" + image + '.png', "rb") as f:
            image = f.read()
    except FileNotFoundError:
        return Response(status=404)
    return Response(image, mimetype='image/png')