from datetime import datetime
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

payload: bytes                      # the original payload
signature: bytes                    # the digital signature
signature_algorithm: str            # the algorithm used to generate the signature
signature_timestamp: datetime       # the signature's timestamp
payload_hash: bytes                 # the payload hash
hash_algorithm: str                 # the algorithm used to calculate the payload hash
cadeia_certificado: list[x509.Certificate]  # the X509 certificate chain
nome: str

with open('response.p7s', 'rb') as arquivo_p7s:
    p7s_bytes: bytes = arquivo_p7s.read()
    arquivo_p7s.close()

cadeia_certificado = pkcs7.load_der_pkcs7_certificates(p7s_bytes)

content_info: cms.ContentInfo = cms.ContentInfo.load(p7s_bytes)
signed_data: cms.SignedData = content_info['content']
signer_info: cms.SignerInfo = signed_data['signer_infos'][0]

payload = signed_data['encap_content_info']['content'].native

signature = signer_info['signature'].native
signature_algorithm = signer_info['signature_algorithm']['algorithm'].native
hash_algorithm = signer_info['digest_algorithm']['algorithm'].native

signed_attrs = signer_info['signed_attrs']
for signed_attr in signed_attrs:
    match signed_attr['type'].native:
        case 'message_digest':
            payload_hash = signed_attr['values'][0].native
        case 'signing_time':
            signature_timestamp = signed_attr['values'][0].native

nome = cadeia_certificado[0].subject
print(nome)
print(signature_timestamp)
