from flask import Response, render_template, request
from config import utils_config
from password import crypt as PasswordCrypt


def util_main(app):
    @app.route("/static/<name>", methods=['GET'])
    def utils_static(name):
        try:
            with open("static/" + name, "rb") as f:
                filebyte = f.read()
        except FileNotFoundError:
            return Response(status=404)
        return Response(filebyte)

    @app.route(utils_config['base_url'] + "/index", methods=['GET'])
    def utils_index():
        return render_template('utils_index.html')

    @app.route(utils_config['base_url'] + "/password/randomid", methods=['POST'])
    def utils_randomid():
        if request.is_json:
            data = request.json
            data['id']