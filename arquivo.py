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

p7s_filepath: str = 'response.p7s'

# load the p7s file
with open(p7s_filepath, 'rb') as f:
    p7s_bytes: bytes = f.read()
    f.close()

# extract the certificater chain
cert_chain = pkcs7.load_der_pkcs7_certificates(p7s_bytes)

# extract the needed structures
content_info: cms.ContentInfo = cms.ContentInfo.load(p7s_bytes)
signed_data: cms.SignedData = content_info['content']
signer_info: cms.SignerInfo = signed_data['signer_infos'][0]

signed_attrs = signer_info['signed_attrs']
for signed_attr in signed_attrs:
    match signed_attr['type'].native:
        case 'signing_time':
            signature_timestamp = signed_attr['values'][0].native

with open('teste.pdf', 'rb') as fh:
    input_buf = BytesIO(fh.read())
w = IncrementalPdfFileWriter(input_buf)

cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
    field_name='Signature', writer=w
)
sig_field_ref = next(cms_writer)

# just for kicks, let's check
assert sig_field_ref.get_object()['/T'] == 'Signature'

timestamp = signature_timestamp
sig_obj = signers.SignatureObject(timestamp=timestamp, subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED)

md_algorithm = 'sha256'
# for demonstration purposes, let's do a certification signature instead
# of a plain old approval signature here
cms_writer.send(
    cms_embedder.SigObjSetup(
        sig_placeholder=sig_obj
    )
)

prep_digest, output = cms_writer.send(
    cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
)
cms_bytes = cms.ContentInfo.load(p7s_bytes)
sig_contents = cms_writer.send(cms_bytes)

with open('output-assinado.pdf', 'wb') as outf:
        outf.write(output.getbuffer())