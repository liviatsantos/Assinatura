import hashlib
import base64
from io import BytesIO

with open('teste.pdf', 'rb') as arquivo_pdf:
    pdf_bytes = arquivo_pdf.read()
    arquivo_pdf.close()

hash = hashlib.sha256(pdf_bytes).hexdigest()
hashbase64 = base64.b64encode(hashlib.sha256(pdf_bytes).digest())
print(hash)
print(hashbase64)
