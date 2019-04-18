from base import config, cache, app
from Flask import request, Response

@app.route("/api/fairy/security/checkinfo", methods=["POST"])
def fairy_checkinfo():
    if request.is_json:
        data = request.json
        md5 = data.get("filemd5")
        size = data.get("size")
