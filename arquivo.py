from datetime import datetime
from pyhanko.sign import signers
from pyhanko.sign.signers import cms_embedder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

from io import BytesIO

input_buf = BytesIO(b'teste.pdf')
w = IncrementalPdfFileWriter(input_buf)

# Phase 1: coroutine sets up the form field, and returns a reference
cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
    field_name='Signature', writer=w
)
sig_field_ref = next(cms_writer)

# just for kicks, let's check
assert sig_field_ref.get_object()['/T'] == 'Signature'

# Phase 2: make a placeholder signature object,
# wrap it up together with the MDP config we want, and send that
# on to cms_writer
#timestamp = datetime.now(tz=tzlocal.get_localzone())
#sig_obj = signers.SignatureObject(timestamp=timestamp, bytes_reserved=8192)
sig_obj = signers.SignatureObject(bytes_reserved=8192)

md_algorithm = 'sha256'
# for demonstration purposes, let's do a certification signature instead
# of a plain old approval signature here
cms_writer.send(
    cms_embedder.SigObjSetup(
        sig_placeholder=sig_obj,
        mdp_setup=cms_embedder.SigMDPSetup(
            md_algorithm=md_algorithm, certify=True,
            docmdp_perms=fields.MDPPerm.NO_CHANGES
        )
    )
)

# Phase 3: write & hash the document (with placeholder)
prep_digest, output = cms_writer.send(
    cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
)
# The `output` variable is a handle to the stream that contains
# the document to be signed, with a placeholder allocated to hold
# the actual signature contents.

# Phase 4: construct the CMS object, and pass it on to cms_writer

# NOTE: I'm using a regular SimpleSigner here, but you can substitute
# whatever CMS supplier you want.

signer: signers.SimpleSigner = FROM_CA
# let's supply the CMS object as a raw bytestring
cms_bytes = signer.sign(
    data_digest=prep_digest.document_digest,
    digest_algorithm=md_algorithm, timestamp=timestamp
).dump()
sig_contents = cms_writer.send(cms_bytes)

# The (signed) output document is in `output` now.
# `sig_contents` holds the content of the signature container
# in the PDF file, including any padding.