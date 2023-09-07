from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, render_template, flash
import os
import requests
from urllib.parse import urlparse,  parse_qs
import json

UPLOAD_FOLDER = '/templates/'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

client_id = "apptestegovbr"
client_secret = "lHbfJhktrIzQybBKvDAE"
redirect_uri ='http://127.0.0.1:5000/callback'
scope = 'sign'
authorization_base_url = 'https://cas.staging.iti.br/oauth2.0/authorize'
token_url = 'https://cas.staging.iti.br/oauth2.0/token'

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/login")
def login():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(authorization_base_url)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
    url_code= urlparse(request.url)
    code = parse_qs(url_code.query)['code'][0]
    token = oauth.fetch_token(token_url, client_secret=client_secret, code=code)
    session['oauth_token'] = token
    return render_template('index.html',logado=True)

@app.route("/certificado")
def certificado():
    url = 'https://assinatura-api.staging.iti.br/externo/v2/certificadoPublico'
    at = session['oauth_token']
    headers = {'Authorization':'Bearer ' + at["access_token"]}
    response = requests.get(url, headers=headers)
    return response.text

@app.route("/assinatura")
def assinatura():
    url = 'https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7'
    at = session['oauth_token']
    hash_assinatura = 'de+/L6UDADapD9lMrsvD7ex3hSf+AdnrD19YKzZK9GY='
    payload = json.dumps({'hashBase64': hash_assinatura })
    headers = {'Content-Type': 'application/json', 'Authorization':'Bearer ' + at["access_token"]}
    response = requests.post(url, headers=headers, data=payload, stream=True)
    
    with open('response.p7s', 'wb') as arquivo_assinatura:
        arquivo_assinatura.write(response.raw.read())
        arquivo_assinatura.close
    return render_template('index.html', assinado=True)

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        else:
            file.save(os.path.join(app.config['UPLOAD_FOLDER']))
        
if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True)


