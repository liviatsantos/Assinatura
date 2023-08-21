from datetime import datetime
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from pyhanko.sign import signers
from pyhanko.sign.signers import cms_embedder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from io import BytesIO
from pyhanko.sign.fields import SigSeedSubFilter

signature_timestamp: datetime

#faz leitura do arquivo da assinatura
with open('response.p7s', 'rb') as arquivo_p7s:
    p7s_bytes: bytes = arquivo_p7s.read()
    arquivo_p7s.close()

cadeia_certificado = pkcs7.load_der_pkcs7_certificates(p7s_bytes)

#conteudo da assinatura
content_info: cms.ContentInfo = cms.ContentInfo.load(p7s_bytes)
signed_data: cms.SignedData = content_info['content']
signer_info: cms.SignerInfo = signed_data['signer_infos'][0]

signed_attrs = signer_info['signed_attrs']
for signed_attr in signed_attrs:
    match signed_attr['type'].native:
        case 'signing_time':
            signature_timestamp = signed_attr['values'][0].native

#faz leitura arquivo que foi assinado
with open('teste.pdf', 'rb') as arquivo_pdf:
    pdf_bytes = BytesIO(arquivo_pdf.read())
    arquivo_pdf.close()    
w = IncrementalPdfFileWriter(pdf_bytes)

cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
    field_name='Signature', writer=w
)
sig_field_ref = next(cms_writer)

#verifica se campo de assinatura foi criado
assert sig_field_ref.get_object()['/T'] == 'Signature'

#cria campos para adicionar no pdf
timestamp = signature_timestamp
sig_obj = signers.SignatureObject(timestamp=timestamp, subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED)
cms_writer.send(
    cms_embedder.SigObjSetup(
        sig_placeholder=sig_obj
    )
)

md_algorithm = 'SHA256'
prep_digest, output = cms_writer.send(
    cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
)

#recupera conteudo CMS do arquivo p7s e envia para cms_writer
cms_bytes = cms.ContentInfo.load(p7s_bytes)
cms_writer.send(cms_bytes)

#gera pdf assinado
with open('teste_assinado.pdf', 'wb') as arquivo_assinado:
    arquivo_assinado.write(output.getbuffer())