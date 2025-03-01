import base64
from fastapi import FastAPI, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

# ✅ Initialize FastAPI
app = FastAPI()

# ✅ Load private key (PKCS#8 format)
PRIVATE_KEY_PATH = r'C:\Users\yekat\private_key_pkcs1.pem'  # Ensure this is the correct path

with open(PRIVATE_KEY_PATH, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

# ✅ Define the request model
class TokenRequest(BaseModel):
    one_time_token: str

# ✅ API Endpoint for Signing Token
@app.post("/sign_token")
async def sign_token(request: TokenRequest):
    one_time_token = request.one_time_token

    # 🔐 Sign the token with RSA PKCS1v15
    signed_token = private_key.sign(
        one_time_token.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # ✅ Encode the signature in Base64 for API compatibility
    signature_base64 = base64.b64encode(signed_token).decode()

    return {"signed_token": signature_base64}
