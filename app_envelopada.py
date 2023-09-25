from pyhanko.sign import signers, fields
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, render_template, send_file
import os
import requests
from urllib.parse import urlparse,  parse_qs
import json
from io import BytesIO
from asn1crypto import cms
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
def ler_arquivo():
    if 'file' in request.files:
        file = request.files['file']
        if file and arquivo_permitido(file.filename):
            pdf_bytes = BytesIO(file.read())
            w = IncrementalPdfFileWriter(pdf_bytes)
            prep_hash = prep_documento(w)
            hashbase64 = base64.b64encode(hashlib.sha256(prep_hash).hexdigest)
            session['hash'] = hashbase64
            nome_arquivo = file.filename
            session['nome_arquivo'] = nome_arquivo.replace('.pdf','_assinado.pdf')
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
    #1.Prepara documento
    hash1 = session['hash'] 
    hash_assinatura = hash1.decode()
    payload = json.dumps({'hashBase64': hash_assinatura })
    headers = {'Content-Type': 'application/json', 'Authorization':'Bearer ' + at["access_token"]}
    response = requests.post(url, headers=headers, data=payload, stream=True)
    if response.ok:
        #salva arquivo assinatura na pasta do projeto
        nome_arquivo = session['nome_arquivo']      
        with open(file=nome_arquivo, mode='wb') as arquivo_assinatura:
            arquivo_assinatura.write(response.raw.read())
            arquivo_assinatura.close
            cms_bytes = cms.ContentInfo.load(arquivo_assinatura)
            out = session['output'] 
            finish_signing(cms_bytes, out)
        return render_template('index.html', assinado=True)
    else:
        return render_template('index.html', assinado=False)

@app.route("/download")
def download():
    nome_arquivo = session['nome_arquivo']
    return send_file(path_or_file=nome_arquivo, download_name=nome_arquivo, as_attachment = True)

def arquivo_permitido(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in TIPO_ARQUIVO

async def prep_documento(w: BasePdfFileWriter):
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name='Assinatura gov.br', embed_validation_info=True, use_pades_lta=False,
            subfilter=fields.SigSeedSubFilter.PADES,
            md_algorithm='sha256'
        ),
        signer=signers.ExternalSigner(
            signature_value=bytes(256)
        ),
    )

    prep_digest, tbs_document, output =  await pdf_signer.async_digest_doc_for_signing(w)
    print(prep_digest)
    session['tbs_documents'] = tbs_document
    session['output'] = output

    return prep_digest.document_digest

async def finish_signing(prep_digest, output_handle):
    cms = session['cms_bytes'] 
    ext_signer = cms
    signed_attrs = await ext_signer.signed_attrs(
        prep_digest.document_digest, 'sha256', use_pades=True
    )
    sig_cms = await ext_signer.async_sign_prescribed_attributes(
        'sha256', signed_attrs=signed_attrs
    )

    await PdfTBSDocument.async_finish_signing(
        output_handle, prepared_digest=prep_digest,
        signature_cms=sig_cms
    )
    #gera pdf assinado
    with open('teste_assinado.pdf', 'wb') as arquivo_assinado:
        arquivo_assinado.write(output_handle.getbuffer())
        arquivo_assinado.close

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    app.secret_key = os.urandom(24)
    app.run(debug=True)