"""Validate an incoming API token with Daywalker Auth, with an RFC 9421 signed request.

Env: DAYWALKER_API_KEY, DAYWALKER_SIGNING_KEY (base64 PKCS#8 Ed25519), DAYWALKER_KEY_ID,
     optional DAYWALKER_URL (default https://auth.daywalker.dev).
Needs: pip install cryptography
"""
import base64, hashlib, json, os, sys, time, urllib.error, urllib.request
from urllib.parse import urlparse

from cryptography.hazmat.primitives.serialization import load_der_private_key

BASE = os.environ.get("DAYWALKER_URL", "https://auth.daywalker.dev")
PATH = "/api/v1/tokens/validate"


def validate_token(token: str) -> dict:
    body = json.dumps({"token": token}, separators=(",", ":")).encode()
    digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    key_id = os.environ["DAYWALKER_KEY_ID"]
    params = f'("@method" "@path" "@authority" "content-digest");created={int(time.time())};keyid="{key_id}";alg="ed25519";nonce="{os.urandom(12).hex()}"'
    base = "\n".join([
        '"@method": POST',
        f'"@path": {PATH}',
        f'"@authority": {urlparse(BASE).netloc}',
        f'"content-digest": {digest}',
        f'"@signature-params": {params}',
    ])
    key = load_der_private_key(base64.b64decode(os.environ["DAYWALKER_SIGNING_KEY"]), None)
    signature = base64.b64encode(key.sign(base.encode())).decode()
    req = urllib.request.Request(BASE + PATH, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ['DAYWALKER_API_KEY']}",
        "Content-Digest": digest,
        "Signature-Input": f"sig1={params}",
        "Signature": f"sig1=:{signature}:",
    })
    try:
        with urllib.request.urlopen(req) as res:
            return json.load(res)
    except urllib.error.HTTPError as err:  # 4xx/5xx still carry a JSON error body
        return json.load(err)


if __name__ == "__main__":
    result = validate_token(sys.argv[1])
    if result.get("valid"):
        print("Authorized user:", result["userId"], "quota:", result["rateLimit"]["remaining"])
    else:
        print(f"Rejected [{result.get('error')}]: {result.get('message')}")
