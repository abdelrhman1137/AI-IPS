"""
auth.py — JWT-based authentication for AI-IDS NIGHTWATCH backend.
Stores credentials in ../credentials.json (same file as the Streamlit version).
"""

import os
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────
SECRET_KEY  = os.environ.get("IDS_SECRET_KEY", "nightwatch-super-secret-key-change-in-prod")
ALGORITHM   = "HS256"
TOKEN_EXPIRE_HOURS = 24

_DIR       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRED_FILE  = os.path.join(_DIR, "credentials.json")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── Models ─────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    email: str

# ── Helpers ────────────────────────────────────────────────────────────────────
def _load_creds() -> dict:
    if not os.path.exists(CRED_FILE):
        return {}
    with open(CRED_FILE, "r") as f:
        return json.load(f)

def _save_creds(creds: dict):
    with open(CRED_FILE, "w") as f:
        json.dump(creds, f)

def _create_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def _verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    email = _verify_token(token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return email

# ── Route handlers (called from main.py) ──────────────────────────────────────
def login(req: LoginRequest) -> TokenResponse:
    creds = _load_creds()
    stored = creds.get(req.email)
    # Support both bcrypt hashes and legacy plain-text passwords (Streamlit era)
    if stored is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if stored.startswith("$2") :
        # bcrypt hash
        try:
            ok = bcrypt.checkpw(req.password.encode('utf-8'), stored.encode('utf-8'))
        except ValueError:
            ok = False
    else:
        # legacy plain-text (backward compat with Streamlit credentials.json)
        ok = (stored == req.password)
    
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = _create_token(req.email)
    return TokenResponse(access_token=token, token_type="bearer", email=req.email)

def register(req: RegisterRequest) -> dict:
    if not req.email or not req.password:
        raise HTTPException(status_code=400, detail="Email and password required")
    creds = _load_creds()
    if req.email in creds:
        raise HTTPException(status_code=409, detail="Email already registered")
    hashed = bcrypt.hashpw(req.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    creds[req.email] = hashed
    _save_creds(creds)
    return {"success": True, "message": "Registered successfully"}
