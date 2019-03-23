from flask import Flask, redirect, url_for
from werkzeug.contrib.fixers import ProxyFix
from flask_dance.contrib.github import make_github_blueprint, github

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = "supersekrit"
blueprint = make_github_blueprint(
    client_id="cafc6b66d1a95033e6ad",
    client_secret="7c322f146ca7c4759c9fd900a930b35b7a65f1ad",
)
app.register_blueprint(blueprint, url_prefix="/login")

@app.route("/login")
def index():
    if not github.authorized:
        return redirect(url_for("github.login"))
    resp = github.get("/user")
    assert resp.ok
    return "You are @{login} on GitHub".format(login=resp.json()["login"])

app.run(ssl_context='adhoc')