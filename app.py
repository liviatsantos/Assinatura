from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, render_template
import os
import requests
from urllib.parse import urlparse,  parse_qs
import json
import hashlib
import base64

TIPO_ARQUIVO = {'pdf'}

app = Flask(__name__)

client_id = ""
client_secret = ""
redirect_uri ='http://127.0.0.1:5000/callback'
scope = 'sign'
authorization_base_url = 'https://cas.staging.iti.br/oauth2.0/authorize'
token_url = 'https://cas.staging.iti.br/oauth2.0/token'

@app.route("/")
def index():
    session.clear()
    return render_template('index.html')

@app.route('/assinar', methods=['POST'])
def salvar_arquivo():
    if 'file' in request.files:
        file = request.files['file']
        if file and arquivo_permitido(file.filename):
            pdf_bytes = file.read()
            hashbase64 = base64.b64encode(hashlib.sha256(pdf_bytes).digest())
            session['hash'] = hashbase64.decode()
    return redirect('/logar')

@app.route("/logar")
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

    #faz requisição ao serviço de assinatura
    url = 'https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7'
    at = session['oauth_token']
    hash_assinatura = session['hash']
    payload = json.dumps({'hashBase64': hash_assinatura })
    headers = {'Content-Type': 'application/json', 'Authorization':'Bearer ' + at["access_token"]}
    response = requests.post(url, headers=headers, data=payload, stream=True)
    
    #salva arquivo assinatura na pasta do projeto
    with open('response.p7s', 'wb') as arquivo_assinatura:
        arquivo_assinatura.write(response.raw.read())
        arquivo_assinatura.close
    return render_template('index.html', assinado=True)

def arquivo_permitido(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in TIPO_ARQUIVO
        
if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    app.secret_key = os.urandom(24)
    app.run(debug=True)


