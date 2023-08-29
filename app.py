from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session
from flask.json import jsonify
import os
import requests
from urllib.parse import urlparse,  parse_qs

app = Flask(__name__)

client_id = ""
client_secret = ""
redirect_uri ='http://127.0.0.1:5000/callback'
scope = 'sign'
authorization_base_url = 'https://cas.staging.iti.br/oauth2.0/authorize'
token_url = 'https://cas.staging.iti.br/oauth2.0/token'

@app.route("/")
def login():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(authorization_base_url)

    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback", methods=["GET"])
def callback():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
    url_code= urlparse(request.url)
    code = parse_qs(url_code.query)['code'][0]

    token = oauth.fetch_token(token_url, client_secret=client_secret, code=code)
    session['oauth_token'] = token
    return jsonify(token)

@app.route("/certificado", methods=["GET"])
def certificado():
    url = 'https://assinatura-api.staging.iti.br/externo/v2/certificadoPublico'
    at = session['oauth_token']
    headers = {'Authorization': 'Bearer ' + at["access_token"]}
   
    r = requests.get(url, headers)
    return r.text

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True)


