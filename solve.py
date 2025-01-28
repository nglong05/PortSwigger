import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

token = ''

with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}")

decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header: {decoded_header}\n")

decoded_token['sub'] = 'administrator'
print(f"Modified token: {decoded_token}\n")

with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )
