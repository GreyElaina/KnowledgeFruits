from os.path import exists as FileExists
from datetime import timedelta

from werkzeug.contrib.fixers import LighttpdCGIRootFix

import model
from base import app, config
import fairy
import customskinapi
import knowledgeapi
import yggdrasil
import texture
import yggdrasil_group
import emailverify
from time import sleep
from flask import render_template

if __name__ == '__main__':
    model.db['log'].create_tables([model.log_kf, model.log_yggdrasil])
    if FileExists('./data/global.db'):
        model.db['global'].create_tables([model.profile, model.user, model.textures, model.banner, model.group, model.member, model.review, model.message, model.setting])
    if False in [FileExists(config.KeyPath.Private), FileExists(config.KeyPath.Public)]:
        print("Please use openssl to gen a rsa privkey and a rsa pubkey.")
        exit(1)
    app.wsgi_app = LighttpdCGIRootFix(app.wsgi_app)
    from paste.translogger import TransLogger
    import waitress
    try:
        waitress.serve(
            TransLogger(app,
                setup_console_handler=True,
                format="[%(time)s][%(REQUEST_METHOD)s][%(status)s] \"%(REQUEST_URI)s\"",
            ),
            host=config.AdditionalParameters.bind.host,
            port=config.AdditionalParameters.bind.port
        )
    except KeyboardInterrupt:
        print("KnowledgeFruits will exit after 5 seconds.")
        sleep(5)
        exit()
    #app.run(port=5001, debug=True)