from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from user_core import User


class VerifyRequest(BaseModel):
    name: str


app = FastAPI()


user = User()

user.generate_keys()
cert = user.obtain_certificate()


@app.get("/")
def root():
    return {
        "name": user.name,
        "keys": user.keys,
        "certificate": user.certificate
    }


@app.post("/verify_cert")
def verify_certificate(req: VerifyRequest):
    cert = user.get_cert_by_name(req.name)
    if not cert:
        return {"valid": False}
    result = user.verify_certificate(cert)
    return {"valid": result}


@app.post("/get_cert_by_name")
def get_cert_by_name_endpoint(req: VerifyRequest):
    try:
        cert = user.get_cert_by_name(req.name)
        return cert
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/revoke_my_cert")
def revoke_my_cert():
    return {
        "status": user.revoke_my_cert()
    }

@app.post("/update_cert")
def update_cert():
    if not user.obtain_certificate():
        return {
            "status": False
        }
    else:
        return {
            "status": True
        }
