from os.path import exists as FileExists
from datetime import timedelta

from werkzeug.contrib.fixers import LighttpdCGIRootFix

import model
from base import app, config, raw_config, cache, Token
import fairy
import customskinapi
import knowledgeapi
import yggdrasil
import texture

if __name__ == '__main__':
    if FileExists('./data/global.db'):
        model.db['global'].create_tables([model.profile, model.user, model.textures])
    if False in [FileExists(config.KeyPath.Private), FileExists(config.KeyPath.Public)]:
        from paramiko.rsakey import RSAKey, SSHException
        def gen_keys(key=""):
            output = StringIO.StringIO()
            sbuffer = StringIO.StringIO()
            key_content = {}
            if not key:
                try:
                    key = RSAKey.generate(2048)
                    key.write_private_key(output)
                    private_key = output.getvalue()
                except IOError:
                    raise IOError('gen_keys: there was an error writing to the file')
                except SSHException:
                    raise SSHException('gen_keys: the key is invalid')
            else:
                private_key = key
                output.write(key)
                key = RSAKey.from_private_key(output)

            for data in [key.get_name(),
                         " ",
                         key.get_base64(),
                         " %s@%s" % ("magicstack", os.uname()[1])]:
                sbuffer.write(data)
            public_key = sbuffer.getvalue()
            key_content['public_key'] = public_key
            key_content['private_key'] = private_key
            return key_content
    app.wsgi_app = LighttpdCGIRootFix(app.wsgi_app)
    from paste.translogger import TransLogger
    import waitress
    waitress.serve(
        TransLogger(app,
            setup_console_handler=True,
            format="[%(time)s][%(REQUEST_METHOD)s][%(status)s] \"%(REQUEST_URI)s\"",
        ),
        host='0.0.0.0',
        port=5001
    )
    #app.run(port=5001, debug=True)