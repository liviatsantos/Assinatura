import requests
from requests_oauthlib import OAuth2Session

cliente =''
secret = ''
redirect_uri ='https://localhost:8080'
scope = 'sign'
response_type='code'

oauth = OAuth2Session(cliente, redirect_uri=redirect_uri,
                          scope=scope)
authorization_url, state = oauth.authorization_url('https://cas.staging.iti.br/oauth2.0/authorize')
print(authorization_url)

