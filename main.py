import os
import base64
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

app = FastAPI()

# ✅ 1. Load the private key from Railway Environment Variables
private_key_pem = os.getenv("PRIVATE_KEY")

if not private_key_pem:
    raise Exception("❌ PRIVATE_KEY environment variable is missing!")

# ✅ Fix formatting (Restore line breaks)
formatted_private_key = private_key_pem.replace("\\n", "\n").encode()

# ✅ Convert PEM string back to a private key object
private_key = serialization.load_pem_private_key(
    formatted_private_key,
    password=None
)

# ✅ Define request structure
class TokenRequest(BaseModel):
    one_time_token: str

# ✅ API Endpoint to Sign Token
@app.post("/sign_token")
async def sign_token(request: TokenRequest):
    one_time_token = request.one_time_token

    # 🔐 Sign the token with RSA PKCS1v15
    signed_token = private_key.sign(
        one_time_token.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # ✅ Encode the signature in Base64
    signature_base64 = base64.b64encode(signed_token).decode()

    return {"signed_token": signature_base64}

# ✅ Run the FastAPI app on port 8080 (Required for Railway)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)