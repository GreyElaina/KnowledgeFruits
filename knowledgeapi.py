
from base import config, cache_secureauth, app, Token, raw_config, cache_token
from flask import request, Response
from urllib.parse import parse_qs, urlencode, urlparse
import json
import uuid
import model
import hashlib
import password
import base64
import utils
import re
import time
from urllib.parse import urlencode
import datetime
import random
import Exceptions
import group as G


@app.route("/api/knowledgefruits/")
def serverinfo():
    return Response(json.dumps({
        "Yggdrasil": {
            "BaseUrl": config.const.base,
            "info": {
                "meta": config.YggdrasilIndexData,
                "skinDomains": config.SiteDomain if "SiteDomain" in config.__dict__ else [urlparse(request.url).netloc.split(":")[0]],
                "signaturePublickey": open(config.KeyPath.Public, 'r').read()
            }
        },
        "TokenTime": raw_config['TokenTime']
    }), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/authenticate/security/signin", methods=['POST'])
def kf_randomkey_signin():
    if request.is_json:
        data = request.json
        print(data)
        Randomkey = password.CreateSalt(length=8)
        authid = data.get("authid")
        user_result = model.getuser(data['username'])
        if not user_result:
            print("why!!!!")
            raise Exceptions.InvalidCredentials()
        salt = user_result.passwordsalt
        if user_result:
            IReturn = {
                "authId": authid,
                "HashKey": Randomkey,
                "username": user_result.email,
                "salt": salt
            }
            cache_secureauth.set(authid, {
                "HashKey": Randomkey,
                "username": user_result.email,
                "salt": salt,
                "VerifyValue": user_result.password,
                "authId": authid,
                "inorderto": "signin"
            }, ttl=30)
            print("分".join([salt, authid, Randomkey]))
            return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)


@app.route("/api/knowledgefruits/authenticate/security/signout", methods=['POST'])
def kf_randomkey_signout():
    if request.is_json:
        data = request.json
        Randomkey = password.CreateSalt(length=8)
        authid = data.get("authid")
        user_result = model.getuser(data['username'])
        if not user_result:
            raise Exceptions.InvalidCredentials()
        salt = user_result.passwordsalt
        if user_result:
            IReturn = {
                "authId": authid,
                "HashKey": Randomkey,
                "username": user_result.email,
                "salt": salt
            }
            cache_secureauth.set(authid, {
                "HashKey": Randomkey,
                "username": user_result.email,
                "salt": salt,
                "VerifyValue": user_result.password,
                "authId": authid,
                "inorderto": "signout"
            }, ttl=30)
            print(RandomKey, salt, authid)
            return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
        else:
            return Response(status=403)


@app.route("/api/knowledgefruits/authenticate/security/verify", methods=['POST'])
def kf_login_verify():
    if request.is_json:
        data = request.json
        Data = cache_secureauth.get(data.get("authId"))
        if not Data:
            return Response(status=403)
        else:
            user_result = model.getuser(Data['username'])
            if user_result:
                AuthRequest = password.crypt(
                    user_result.password, Data['HashKey'])
                print(AuthRequest)
                if AuthRequest == data['Password']:
                    if Data.get("inorderto") == "signin":
                        notDoubleProfile = False
                        Profileresult = model.getprofile_createby(
                            user_result.uuid)
                        if len(Profileresult) == 1:
                            notDoubleProfile = True
                            SelectedProfile = model.format_profile(
                                Profileresult.get())

                        AccessToken = str(uuid.uuid4()).replace("-", "")
                        ClientToken = str(uuid.uuid4()).replace("-", "")

                        cache_token.set(AccessToken, {
                            "clientToken": ClientToken,
                            "bind": Profileresult.get().uuid if notDoubleProfile else None,
                            "user": user_result.uuid,
                            "group": "global",
                            "createTime": int(time.time())
                        }, ttl=config.TokenTime.RefrushTime * config.TokenTime.TimeRange)
                        IReturn = {
                            "accessToken": AccessToken,
                            "clientToken": ClientToken,
                        }
                        cache_secureauth.delete(data['authId'])
                        if data.get("requestUser"):
                            IReturn['metadata'] = {
                                "user": {
                                    "userId": user_result.uuid
                                }
                            }
                        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')
                    if Data.get("inorderto") == "signout":
                        result = Token.getalltoken(user_result)
                        if result:
                            for i in result:
                                cache_secureauth.delete(i)
                        return Response(status=204)
                else:
                    cache_secureauth.delete(data['authId'])
                    raise Exceptions.InvalidCredentials()
            else:
                cache_secureauth.delete(data['authId'])
                return Response(status=403)


@app.route("/api/knowledgefruits/authenticate/password/test", methods=['POST'])
def kf_passwd_test():
    if not re.match(utils.StitchExpression(config.reMatch.UserPassword), request.data.decode()):
        return Response(status=400)
    else:
        return Response(status=204)


@app.route("/api/knowledgefruits/authenticate/email/test", methods=['POST'])
def kf_email_test():
    if not re.match(utils.StitchExpression(config.reMatch.UserEmail), request.data.decode()):
        return Response(status=400)
    else:
        return Response(status=204)


@app.route("/api/knowledgefruits/authenticate/password/change/<username>", methods=['POST'])
def kf_user_changepasswd(username):
    if request.is_json:
        data = request.json
        user_result = model.getuser(username)
        if user_result:
            AccessToken = data['accessToken']
            ClientToken = data['clientToken'] if 'clientToken' in data else None
            if not ClientToken:
                token_result_boolean = model.is_validate(AccessToken)
                token = model.gettoken(AccessToken)
            else:
                token_result_boolean = model.is_validate(
                    AccessToken, ClientToken)
                token = model.gettoken(AccessToken, ClientToken)
            if token_result_boolean and token:
                # 如果Token有效
                # 开始解析由公钥(/api/yggdrasil)加密的东西
                # 这玩意是个base64
                encrypt = base64.b64decode(data['Password'])
                decrypt_errorMessage = password.decrypt(
                    encrypt, config.KeyPath.Private)
                user = model.getuser(token.email)
                if password.crypt(decrypt_errorMessage, user.passwordsalt) == user.password:
                    return Response(status=204)
                newsalt = utils.CreateSalt(length=8)
                newpassword = password.crypt(decrypt_errorMessage, newsalt)
                user.password = newpassword
                user.passwordsalt = newsalt
                user.save()
                # 开始否决所有的Token
                model.token.delete().where(model.token.email == user.email).execute()
                return Response(status=204)
            else:
                raise Exceptions.InvalidToken()
        else:
            raise Exceptions.InvalidToken()


@app.route("/api/knowledgefruits/search/textures/<path:args>")
def kf_texturesinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i]: args.split("/")[i + 1]
            for i in range(len(args.split("/")))[::2]}
    Args.pop("isPrivate")
    content = [model.textures.__dict__[i].field == Args[i]
               for i in Args.keys()][0]
    for i in [model.textures.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    try:
        return Response(json.dumps([
            model.kf_format_textures(i) for i in model.findtextures(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)


@app.route("/api/knowledgefruits/search/profiles/<path:args>")
def kf_profileinfo(args):
    if (len(args.split("/")) % 2) != 0:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "参数格式错误"
        }), mimetype='application/json; charset=utf-8', status=403)
    Args = {args.split("/")[i]: args.split("/")[i + 1]
            for i in range(len(args.split("/")))[::2]}
    content = [model.profile.__dict__[i].field == Args[i]
               for i in Args.keys()][0]
    for i in [model.profile.__dict__[i].field == Args[i] for i in Args.keys()][1:]:
        content = content & i
    try:
        return Response(json.dumps([
            model.kf_format_profile(i) for i in model.findprofile(content)
        ]), mimetype='application/json; charset=utf-8')
    except KeyError as e:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "预料之外的参数传入"
        }), mimetype='application/json; charset=utf-8', status=403)


@app.route("/api/knowledgefruits/search/id/user/<email>")
def kf_search_user_email(email):
    result = model.getuser(email)
    if not result:
        return Response(json.dumps({
            "error": "WrongArgs",
            "errorMessage": "错误的参数"
        }), mimetype='application/json; charset=utf-8', status=403)
    return Response(json.dumps({"uuid": result.uuid}), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/authenticate/simple/refrush", methods=['GET', "POST"])
def kf_authenticate_simple_refrush():
    if request.is_json:
        data = request.json
        Can = False
        AccessToken = data.get('accessToken')
        ClientToken = data.get("clientToken", str(
            uuid.uuid4()).replace("-", ""))
        IReturn = {}
        if 'clientToken' in data:
            OldToken = Token.gettoken_strict(
                AccessToken, data.get("clientToken"))
        else:
            OldToken = Token.gettoken_strict(AccessToken)
        if not OldToken:
            raise Exceptions.InvalidToken()

        if int(time.time()) >= OldToken.get("createTime") + (config.TokenTime.RefrushTime * config.TokenTime.TimeRange):
            raise Exceptions.InvalidToken()
        NewAccessToken = str(uuid.uuid4()).replace('-', '')
        cache_token.set(".".join(["token", NewAccessToken]), {
            "clientToken": OldToken.get('clientToken'),
            "bind": "",
            "user": OldToken.get("user"),
            "createTime": int(time.time())
        }, ttl=config.TokenTime.RefrushTime * config.TokenTime.TimeRange)
        cache_token.delete(".".join(["token", AccessToken]))
        IReturn['accessToken'] = NewAccessToken
        IReturn['clientToken'] = OldToken.get('clientToken')
        return Response(json.dumps(IReturn), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/simple/authserver/validate", methods=['POST'])
def kf_validate():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")
        result = Token.gettoken_strict(AccessToken, ClientToken)
        if not result:
            raise Exceptions.InvalidToken()
        else:
            if Token.is_validate_strict(AccessToken, ClientToken):
                raise Exceptions.InvalidToken()
            else:
                return Response(status=204)


@app.route("/api/knowledgefruits/simple/authserver/invalidate", methods=['POST'])
def kf_invalidate():
    if request.is_json:
        data = request.json
        AccessToken = data['accessToken']
        ClientToken = data.get("clientToken")

        result = Token.gettoken(AccessToken, ClientToken)
        if result:
            cache_token.delete(".".join(['token', AccessToken]))
        else:
            if ClientToken:
                raise Exceptions.InvalidToken()
        #User = model.user.get(email=result.email)
        '''if User.permission == 0:
            return Response(simplejson.dumps({
                'error' : "ForbiddenOperationException",
                'errorMessage' : "You have been banned by the administrator, please contact the administrator for help"
            }), status=403, mimetype='application/json; charset=utf-8')'''
        return Response(status=204)


@app.route("/api/knowledgefruits/profile/<profileid>/", methods=["GET"])
def kf_profile_info(profileid):
    result = model.getprofile_id(profileid)
    if not result:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "no such profile."
        }), status=403, mimetype='application/json; charset=utf-8')
    return Response(json.dumps(model.kf_format_profile(result.get())), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/profile/<profileid>/skin", methods=["GET"])
def kf_profile_skin(profileid):
    result = model.getprofile_id(profileid)
    if not result:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "no such profile."
        }), status=403, mimetype='application/json; charset=utf-8')
    data = result.get()
    if not data.skin:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "the profile has no any skin."
        }), status=403)
    return Response(json.dumps(model.kf_format_textures(model.gettexture(data.skin))), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/profile/<profileid>/cape", methods=["GET"])
def kf_profile_cape(profileid):
    result = model.getprofile_id(profileid)
    if not result:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "no such profile."
        }), status=403, mimetype='application/json; charset=utf-8')
    data = result.get()
    if not data.cape:
        return Response(json.dumps({
            "error": "ForbiddenOperationException",
            "errorMessage": "the profile has no any cape."
        }), status=403)
    return Response(json.dumps(model.kf_format_textures(model.gettexture(data.cape))), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/profile/<profileid>/skin/change", methods=["POST"])
def kf_profile_skin_change(profileid):
    if request.is_json:
        data = request.json
        result = model.getprofile_id(profileid)
        if not result:
            return Response(json.dumps({
                "error": "ForbiddenOperationException",
                "errorMessage": "no such profile."
            }), status=403, mimetype='application/json; charset=utf-8')
        result = result.get()
        accessToken = data.get("accessToken")

        if not accessToken:
            return Response(json.dumps({
                "error": "ForbiddenOperationException",
                "errorMessage": "no such profile."
            }), status=403, mimetype='application/json; charset=utf-8')

        if Token.is_validate_strict(accessToken):
            raise Exceptions.InvalidToken()

        user = Token.getuser_byaccessToken(accessToken)

        if model.isBanned(user):
            raise Exceptions.InvalidToken()

        texture = model.gettexture(data.get("texture"))

        if not texture:
            raise Exceptions.InvalidToken()

        if texture.isPrivate:
            if texture.userid != user.uuid:
                raise Exceptions.InvalidToken()

        if texture.type != "skin":
            raise Exceptions.InvalidToken()

        if result.skin == texture.textureid:
            return Response(status=204)

        result.skin = texture.textureid
        result.save()
        return Response(status=204)


@app.route("/api/knowledgefruits/profile/<profileid>/cape/change", methods=["POST"])
def kf_profile_cape_change(profileid):
    if request.is_json:
        data = request.json
        result = model.getprofile_id(profileid)
        if not result:
            return Response(json.dumps({
                "error": "ForbiddenOperationException",
                "errorMessage": "no such profile."
            }), status=403, mimetype='application/json; charset=utf-8')
        result = result.get()
        accessToken = data.get("accessToken")

        if not accessToken:
            return Response(json.dumps({
                "error": "ForbiddenOperationException",
                "errorMessage": "no such profile."
            }), status=403, mimetype='application/json; charset=utf-8')

        if Token.is_validate_strict(accessToken):
            raise Exceptions.InvalidToken()

        user = Token.getuser_byaccessToken(accessToken)

        if model.isBanned(user):
            raise Exceptions.InvalidToken()

        texture = model.gettexture(data.get("texture"))

        if not texture:
            raise Exceptions.InvalidToken()

        if texture.isPrivate:
            if texture.userid != user.uuid:
                raise Exceptions.InvalidToken()

        if texture.type != "cape":
            raise Exceptions.InvalidToken()

        if result.cape == texture.textureid:
            return Response(status=204)

        result.cape = texture.textureid
        result.change_time = datetime.datetime.now()
        result.save()
        return Response(status=204)


@app.route("/api/knowledgefruits/group")
def kf_group_root():
    return Response(json.dumps({
        "group_number": len(model.group.select()),
    }), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces")
def kf_group_interfaces():
    return Response(json.dumps([
        "create",
        "report",
        "report.join",
        "signout"
    ]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/create", methods=["POST"])
def kf_group_interfaces_create():
    if request.is_json:
        data = request.json
        name = data.get("name")
        joinway = data.get("joinway", "public_join")
        if joinway not in ["public_join", "public_join_review", "private"]:
            raise Exceptions.InvalidToken()
        if not re.match(r"[a-zA-Z0-9\u4E00-\u9FA5_-]{4,16}$", name):
            raise Exceptions.InvalidToken()
        if model.group.select().where(model.group.name == name):
            raise Exceptions.InvalidToken()

        accessToken = data.get("accessToken")
        clientToken = data.get("clientToken")
        if not accessToken:
            raise Exceptions.InvalidToken()
        if Token.is_validate_strict(accessToken, clientToken):
            raise Exceptions.InvalidToken()
        token = Token.gettoken_strict(accessToken, clientToken)
        user_uuid = model.getuser_uuid(token.get("user")).uuid
        new_group = model.group(name=name, creater=user_uuid, manager=user_uuid,
                                create_date=datetime.datetime.now(), joinway=joinway)
        new_group.save()
        new_manager = model.member(
            user=user_uuid, group=new_group.id, permission="super_manager")
        return Response(json.dumps({
            "groupId": new_group.uuid,
            "timestamp": new_group.create_date.timestamp()
        }), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/report/join/<group_id>", methods=['POST'])
def kf_group_interfaces_report_join(group_id):
    if not request.is_json:
        raise Exceptions.InvalidToken()
    data = request.json

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    if not model.group.select().where(model.group.uuid == group_id):
        raise Exceptions.InvalidToken()
    group = G.get_group(group_id)
    if group.joinway not in ["public_join", "public_join_review"]:
        raise Exceptions.InvalidToken()

    if model.member.select().where(
        (model.member.is_disabled == False) &
        (model.member.user == user_uuid) &
        (model.member.group == group.id)
    ):
        raise Exceptions.InvalidToken()

    if group.joinway == "public_join":
        new = model.member(user=user_uuid, group=group_id,
                           permission="common_user")
        new.save()
        return Response(json.dumps(model.kf_format_group_public(group)), mimetype='application/json; charset=utf-8')
    if group.joinway == "public_join_review":
        review = model.review(user=user_uuid, group=group.id)
        review.save()
        return Response(json.dumps({
            "reviewId": review.id
        }), mimetype='application/json; charset=utf-8')
    if group.joinway == 'private':
        raise Exceptions.InvalidToken()


@app.route("/api/knowledgefruits/group/interfaces/signout/<group_id>", methods=['POST'])
def kf_group_interfaces_signout(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    if not model.group.select().where(model.group.uuid == group_id):
        raise Exceptions.InvalidToken()
    group: model.group = G.get_group(group_id)

    known = G.get_member(group_id, user_uuid)
    if known.permission == "super_manager":
        if not data.get("force"):
            raise Exceptions.InvalidToken()
        else:
            manager_result = model.member.select().where(
                (model.member.is_disabled == False) &
                (model.member.permission == "manager") &
                (model.member.group == group_id)
            )
            if manager_result:
                # 有其他管理员可以被任命为组管理员
                # 随!机!选!择!
                manager_selected = manager_result[random.randint(
                    0, len(manager_result) - 1)]
                manager_result.permission = "super_manager"
                manager_result.save()
                model.message(
                    to=manager_result.user,
                    title='您已成为组 "%(groupname)s" 的组管理员' % (group.name),
                    body='因该组的原组管理员的退出, 您已成为该组的组管理员.',
                    extra=json.dumps({
                        "type": "group"
                    })
                )
            else:
                # 通知一波然后删掉, 解散的组不需要
                now_member = model.member.select().where(
                    (model.member.is_disabled == False) &
                    (model.member.group == group_id) &
                    (model.member.user != user_uuid)
                )
                for i in now_member:
                    model.message(
                        to=i.user,
                        title='您已被清理出组 "%(groupname)s"' % (group.name),
                        body="因该组的原组管理员的退出, 您已被清理出该组."
                    ).save()
                model.member.delete().where(model.member.group == group_id).execute()
    else:
        known.is_disabled = True
        known.move_times += 1
        known.save()
        manager_result = model.member.select().where(
            (model.member.is_disabled == False) &
            ((model.member.permission == "manager") | (model.member.permission == "super_manager")) &
            (model.member.group == group_id)
        )
        for i in manager_result:
            model.message(
                to=i.user,
                title='%(user)s 退出组 "%(groupname)s"' % (
                    model.getuser_uuid(user_uuid).username, group.name),
                body="因该成员的主动申请, 该成员已退出该组."
            ).save()
    return Response(status=204)


@app.route("/api/knowledgefruits/message/", methods=['POST'])
def kf_message():
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    return Response(json.dumps([{
        "title": i.title,
        "body": i.body
    } for i in model.message.select().where(model.message.to == user_uuid)]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/message/unread", methods=['POST'])
def kf_message_unread():
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    return Response(json.dumps([{
        "title": i.title,
        "body": i.body
    } for i in model.message.select().where((model.message.to == user_uuid) & (model.message.is_read == False))]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/message/already-read", methods=['POST'])
def kf_message_alreadyRead():
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    return Response(json.dumps([{
        "title": i.title,
        "body": i.body
    } for i in model.message.select().where((model.message.to == user_uuid) & (model.message.is_read == True))]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>", methods=["POST"])
def kf_group_interfaces_manage(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == user_uuid) &
        (model.member.is_disabled == False)
    )
    if not selectResult:
        raise Exceptions.InvalidToken()
    selectResult = selectResult.get()
    return Response(status=[403, 204][selectResult.permission in ['manager', 'super_manager']])


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/kick/<kick_id>", methods=["POST"])
def kf_group_interfaces_manage_kick(group_id, kick_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    selectResult = model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == kick_id) &
        (model.member.is_disabled == False)
    )
    if not selectResult:
        raise Exceptions.InvalidRequestData()
    selectResult = selectResult.get()
    selectResult.is_disabled = True
    selectResult.move_times += 1
    selectResult.be_kicked_times_total += 1
    selectResult.save()
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/ban/<kick_id>/user", methods=["POST"])
def kf_group_interfaces_manage_ban_user(group_id, kick_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    selectResult = model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == kick_id) &
        (model.member.is_disabled == False)
    )
    if not selectResult:
        raise Exceptions.InvalidRequestData()
    selectResult = selectResult.get()

    ban = model.banner(
        user=selectResult.user,
        create_time=datetime.datetime.now(),
        group=group_id,
        until=datetime.datetime.fromtimestamp(
            time.time() + float(int(data.get("after"))))
    )
    ban.save()
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/ban/<kick_id>/profile/<profile_id>", methods=["POST"])
def kf_group_interfaces_manage_ban_profile(group_id, kick_id, profile_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    selectResult = model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == kick_id) &
        (model.member.is_disabled == False)
    )
    if not selectResult:
        raise Exceptions.InvalidRequestData()
    selectResult = selectResult.get()

    profile = model.profile.select().where(
        (model.profile.uuid == profile_id) &
        (model.profile.createby == user_uuid)
    )
    if not profile:
        raise Exceptions.InvalidRequestData()

    ban = model.banner(
        user=kick_id,
        profile=profile.get().profile_id,
        create_time=datetime.datetime.now(),
        group=group_id,
        until=datetime.datetime.fromtimestamp(
            time.time() + float(int(data.get("after"))))
    )
    ban.save()
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/manager/up/<user_id>", methods=["POST"])
def kf_group_interfaces_manage_manager_up(group_id, user_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    G.is_super_manager(group_id, user_id)

    selectResult = G.get_member_common_user(group_id, user_id)

    selectResult.permission = "manager"
    selectResult.manageup_number += 1
    selectResult.save()

    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/manager/down/<user_id>", methods=["POST"])
def kf_group_interfaces_manage_manager_down(group_id, user_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    G.is_super_manager(group_id, user_id)

    selectResult = G.isManager(group_id, user_id)

    selectResult.permission = "common_user"
    selectResult.managedown_number += 1
    selectResult.save()
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkban/", methods=["POST"])
def kf_group_interfaces_manage_checkban(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    try:
        page = int(data.get("range", 1))
    except ValueError:
        return Response(json.dumps({
            'error': "ForbiddenOperationException",
            'errorMessage': "Invalid request args."
        }), status=403, mimetype='application/json; charset=utf-8')

    return Response(json.dumps([
        (lambda x: {
            "create": x.create_time.timestamp(),
            "until": x.until.timestamp(),
            "length": x.until.timestamp() - x.create_time.timestamp(),
            ["user", "profile"][bool(x.profile)]: [x.profile, x.user][bool(x.profile)],
            "uuid": x.user
        })(i) for i in model.banner.select().where(model.banner.group == group_id)[15*(page - 1):15 * page]
    ]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkban/<user_id>", methods=["POST"])
def kf_group_interfaces_manage_checkban_user(group_id, user_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    if model.member.select().where(
        (model.member.group == group_id) &
        (model.member.user == user_id) &
        (model.member.is_disabled == False)
    ):
        raise Exceptions.InvalidToken()

    return Response(json.dumps([
        (lambda x: {
            "create": x.create_time.timestamp(),
            "until": x.until.timestamp(),
            "length": x.until.timestamp() - x.create_time.timestamp(),
            [b"user", "profile"][bool(x.profile)]: [b"INSTEAD", x.profile][not bool(x.profile)],
            "uuid": x.user
        })(i) for i in model.banner.select().where((model.banner.group == group_id) & (model.banner.user == user_id))
    ], skipkeys=True), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin", methods=["POST"])
def kf_group_interfaces_manage_checkjoin(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps([(lambda x: {
        "id": x.id,
        "user": x.user,
        "time": x.time.timestamp(),
        "enabled": x.isEnabled,
        "accessed": x.isAccessed
    })(i) for i in model.review.select().where(
        (model.review.group == group_id)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/enabled", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_enabled(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps([(lambda x: {
        "id": x.id,
        "user": x.user,
        "time": x.time.timestamp(),
        "accessed": x.isAccessed
    })(i) for i in model.review.select().where(
        (model.review.group == group_id) &
        (model.review.isEnable == True)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/non-enabled", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_non_enabled(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps([(lambda x: {
        "id": x.id,
        "user": x.user,
        "time": x.time.timestamp(),
        "accessed": x.isAccessed
    })(i) for i in model.review.select().where(
        (model.review.group == group_id) &
        (model.review.isEnable == False)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/accessed", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_accessed(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps([(lambda x: {
        "id": x.id,
        "user": x.user,
        "time": x.time.timestamp(),
        "enabled": x.isEnabled,
    })(i) for i in model.review.select().where(
        (model.review.group == group_id) &
        (model.review.isAccessed == True)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/accessed", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_non_accessed(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps([(lambda x: {
        "id": x.id,
        "user": x.user,
        "time": x.time.timestamp(),
        "enabled": x.isEnabled,
    })(i) for i in model.review.select().where(
        (model.review.group == group_id) &
        (model.review.isAccessed == False)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/<review_id>", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_info(group_id, review_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    selectResult = model.review.select().where(
        (model.review.id == review_id) &
        (model.review.group == group_id)
    )
    if not selectResult:
        raise Exceptions.InvalidToken()
    selectResult = selectResult.get()
    return Response(json.dumps({
        "id": selectResult.id,
        "user": selectResult.user,
        "time": selectResult.time.timestamp(),
        "enabled": selectResult.isEnabled,
        "accessed": selectResult.isAccessed
    }), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/<review_id>/access", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_access(group_id, review_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user = model.getuser_uuid(token.get("user"))
    user_uuid = user.uuid
    group = G.get_group(group_id)

    manager = G.isManager(group_id, user_uuid)

    selectResult = model.review.select().where(
        (model.review.id == review_id) &
        (model.review.group == group_id)
    )
    if not selectResult:
        raise Exceptions.InvalidToken()
    selectResult = selectResult.get()
    if selectResult.isEnable != True:
        raise Exceptions.InvalidRequestData()
    selectResult.isEnable = False
    selectResult.isAccessed = True
    if not model.member.select().where(
        (model.member.is_disabled == True) &
        (model.member.group == group_id) &
        (model.member.user == user_uuid)
    ):
        newmember = model.member(
            user=selectResult.user,
            group=selectResult.group,
            permission="common_user"
        )
        newmember.save()
    else:
        joined_member = model.member.select().where(
            (model.member.is_disabled == True) &
            (model.member.group == group_id) &
            (model.member.user == user_uuid)
        ).get()
        joined_member.join_times += 1
        joined_member.is_disabled = False

    for i in model.member.select().where(
        (model.member.group == selectResult.group) &
        ((model.member.permission == "manager") | (model.member.permission == "super_manager")) &
        (model.member.is_disabled == True) &
        (model.member.user != manager.uuid)
    ):
        model.message(
            to=i.user,

            title="用户 %(user)s 面向组 %(group)s 的加组申请被通过" % (
                [user.uuid, user.username][bool(user.username)], group.name),
            body="用户 %(user)s 面向组 %(group)s 的加组申请被组管理员 %(manager)s 通过" % ([user.uuid, user.username][bool(
                user.username)], group.name, [manager.uuid, manager.username][bool(manager.username)]),
            extra=json.dumps({
                "user": user_uuid,
                "group": group.id,
                "manager": manager.uuid
            })
        )
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/<review_id>/refuse", methods=["POST"])
def kf_group_interfaces_manage_checkjoin_refuse(group_id, review_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user = model.getuser_uuid(token.get("user"))
    user_uuid = user.uuid
    group = G.get_group(group_id)

    manager = G.isManager(group_id, user_uuid)

    selectResult = model.review.select().where(
        (model.review.id == review_id) &
        (model.review.group == group_id)
    )
    if not selectResult:
        raise Exceptions.InvalidToken()
    selectResult = selectResult.get()
    if selectResult.isEnable != True:
        raise Exceptions.InvalidRequestData()
    selectResult.isEnable = False
    selectResult.isAccessed = False

    for i in model.member.select().where(
        (model.member.group == selectResult.group) &
        ((model.member.permission == "manager") | (model.member.permission == "super_manager")) &
        (model.member.is_disabled == True) &
        (model.member.user != manager.uuid)
    ):
        model.message(
            to=i.user,

            title="用户 %(user)s 面向组 %(group)s 的加组申请被拒绝" % (
                [user.uuid, user.username][bool(user.username)], group.name),
            body="用户 %(user)s 面向组 %(group)s 的加组申请被组管理员 %(manager)s 拒绝" % ([user.uuid, user.username][bool(
                user.username)], group.name, [manager.uuid, manager.username][bool(manager.username)]),
            extra=json.dumps({
                "user": user_uuid,
                "group": group.id,
                "manager": manager.uuid
            })
        )
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/setting", methods=['POST'])
def kf_group_interfaces_manage_setting(group_id):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    group = G.get_group(group_id)

    selectResult = G.isManager(group_id, user_uuid)

    return Response(json.dumps({
        "name": group.name,
        "joinway": group.joinway,
        "enable": {
            "yggdrasil": group.enable_yggdrasil,
            "invite": group.enable_invite,
            "public_joinhistory": group.enable_public_joinhistory,
            "public_memberlist": group.enable_public_memberlist
        }
    }), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/setting/change/<setting_name>", methods=['POST'])
def kf_group_interfaces_manage_setting_change(group_id, setting_name):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    group = G.get_group(group_id)

    manager = G.isManager(group_id, user_uuid)

    if setting_name not in [
        "joinway", "name", "enable_yggdrasil", "enable_invite",
        "enable_public_joinhistory", "enable_public_memberlist"
    ]:
        raise Exceptions.InvalidRequestData()

    value = data.get("change_value")

    if setting_name == "joinway":
        if value not in ["public_join", "public_join_review", "private"]:
            raise Exceptions.InvalidRequestData()
        group.joinway = value

    if setting_name == "name":
        if not re.match(r"[a-zA-Z0-9\u4E00-\u9FA5_-]{4,16}$", value):
            raise Exceptions.InvalidRequestData()
        group.name = value

    if setting_name == "enable_yggdrasil":
        if not type(value) == bool:
            raise Exceptions.InvalidRequestData()
        group.enable_yggdrasil = value

    if setting_name == "enable_invite":
        if not type(value) == bool:
            raise Exceptions.InvalidRequestData()
        group.enable_invite = value

    if setting_name == "enable_public_joinhistory":
        if not type(value) == bool:
            raise Exceptions.InvalidRequestData()
        group.enable_public_joinhistory = value

    if setting_name == "enable_public_memberlist":
        if not type(value) == bool:
            raise Exceptions.InvalidRequestData()
        group.enable_public_memberlist = value

    group.save()
    return Response(status=204)


@app.route("/api/knowledgefruits/group/interfaces/list", methods=['POST'])
def kf_group_interfaces_list():
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid
    Response(json.dumps([(lambda x:{
        "id": x.id,
        "name": x.name,
        "create_date": x.create_date.timestamp()
    })(i) for i in model.member.select().where(
        (model.member.is_disabled == False) &
        (model.member.user == user_uuid)
    )]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/<group_id>/list", methods=['GET'])
def kf_group_list_GET(group_id):
    result = model.group.select().where(model.group.id == group_id)
    if not result:
        raise Exceptions.InvalidRequestData()
    result = result.get()
    if not result.enable_public_memberlist:
        raise Exceptions.InvalidToken()
    members = model.member.select().where(
        (model.member.group == result.id) &
        (model.member.is_disabled == False)
    )
    return Response(json.dumps([i.user for i in members]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/<group_id>/joinhistory", methods=['GET'])
def kf_group_joinhistory_GET(group_id):
    result = model.group.select().where(model.group.id == group_id)
    if not result:
        raise Exceptions.InvalidRequestData()
    result = result.get()
    if not result.enable_public_joinhistory:
        raise Exceptions.InvalidToken()
    members = model.member.select().where(
        (model.member.group == result.id) &
        (model.member.is_disabled == False)
    ).order_by(model.member.last_joinserver.desc())[:5]
    return Response(json.dumps([i.user for i in members]), mimetype='application/json; charset=utf-8')


@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/length/", methods=["POST"])
@app.route("/api/knowledgefruits/group/interfaces/manage/<group_id>/checkjoin/length/<extra>", methods=["POST"])
def kf_group_interfaces_manager_checkjoin_length(group_id, extra=None):
    data = G.autodata(request)

    token = G.auto_verify(request)
    user_uuid = model.getuser_uuid(token.get("user")).uuid

    selectResult = G.isManager(group_id, user_uuid)

    if not extra:
        length = model.review.select().where(
            (model.review.group == group_id)
        ).count()
    else:
        if extra not in ["non-enabled", "enabled", "accessed", "non-accessed"]:
            raise Exceptions.InvalidRequestData()
        length = model.review.select().where(
            (model.review.group == group_id) &
            {
                "non-enabled": (model.review.isEnable == False),
                "enabled": (model.review.isEnable == True),
                "accessed": (model.review.isAccessed == True),
                "non-accessed": (model.review.isAccessed == False)
            }[extra]
        ).count()

    return Response(json.dumps({
        "length": length
    }), mimetype='application/json; charset=utf-8')
