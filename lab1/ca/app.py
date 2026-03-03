from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import base64

from ca_core import Repository, CA, certificate_to_dict, crl_to_dict
from gostcrypto import gosthash, gostsignature
from key_generator import generate_gost_private_key

app = FastAPI()

repo = Repository("MainRepo")
ca = CA("MyCA", repo)


class IssueRequest(BaseModel):
    subject_public_key: str
    subject_data: List[str]


class RevokeRequest(BaseModel):
    cert_id: int


class ChallengeVerifyRequest(BaseModel):
    open_key: str
    signature: str


class SignRequest(BaseModel):
    key: str
    data: str


@app.get("/")
def root():
    return {"status": "CA is running"}


@app.get("/me/generate")
def generate():
    private_key = generate_gost_private_key()
    signer = gostsignature.new(
            gostsignature.MODE_256,
            curve=gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
        )
    public_key = signer.public_key_generate(private_key)
    return {
        "private_key": base64.b64encode(private_key).decode(),
        "public_key": base64.b64encode(public_key).decode()
    }


@app.post("/me/sign")
def sign(req: SignRequest):
    signer = gostsignature.new(
        gostsignature.MODE_256,
        curve=gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
    )

    key_bytes = base64.b64decode(req.key)
    data_bytes = base64.b64decode(req.data)

    hasher = gosthash.new("streebog256")
    hasher.update(data_bytes)
    digest = hasher.digest()

    signature = signer.sign(key_bytes, digest)

    return {
        "sign": base64.b64encode(signature).decode()
    }


@app.get("/ca/public-key")
def get_ca_public_key():
    return {
        "public_key": base64.b64encode(ca.public_key).decode()
    }


@app.get("/challenge")
def get_challenge(open_key: str):
    try:
        pubkey = base64.b64decode(open_key)
        challenge = ca.get_challenge(pubkey)
        return {"challenge": base64.b64encode(challenge).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/challenge")
def verify_challenge(req: ChallengeVerifyRequest):
    try:
        pubkey = base64.b64decode(req.open_key)
        signature = base64.b64decode(req.signature)
        validated = ca.verify_challenge(pubkey, signature)
        return {"validated": validated}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/certs")
def issue_certificate_after_challenge(req: IssueRequest):
    try:
        pubkey = base64.b64decode(req.subject_public_key)

        cert = ca.issue_certificate_after_challenge(pubkey, req.subject_data)

        return certificate_to_dict(cert)

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/certs")
def list_certificates():
    return [certificate_to_dict(c) for c in repo.certs]


@app.post("/revoke")
def revoke_certificate(req: RevokeRequest):
    cert = next((c for c in repo.certs if c.id == req.cert_id), None)

    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    ca.revoke_cert(cert)

    return {"status": "revoked"}


@app.get("/crl")
def get_crl():
    if not repo.crls:
        return {"crl": None}

    return crl_to_dict(repo.crls[-1])
