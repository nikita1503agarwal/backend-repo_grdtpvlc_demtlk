import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

import jwt
from passlib.context import CryptContext
import qrcode
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader

from database import db, create_document, get_documents
from bson import ObjectId

# Schemas
from schemas import User, Visitor, Appointment, PassModel, CheckLog

# Security setup
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Visitor Pass Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------- Helpers ---------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_roles(*roles):
    def role_checker(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

# --------------- Models for requests ---------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "employee"

class AppointmentCreateRequest(BaseModel):
    host_user_id: str
    visitor_first_name: str
    visitor_last_name: str
    visitor_email: Optional[EmailStr] = None
    visitor_phone: Optional[str] = None
    purpose: str
    scheduled_at: datetime

# --------------- Routes ---------------
@app.get("/")
def read_root():
    return {"message": "Visitor Pass Management API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response

# Auth
@app.post("/auth/register")
def register(req: RegisterRequest):
    if db["user"].find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=req.name, email=req.email, role=req.role)
    doc = user.model_dump()
    doc["password_hash"] = hash_password(req.password)
    user_id = db["user"].insert_one(doc).inserted_id
    token = create_access_token({"sub": str(user_id), "role": req.role})
    return {"token": token, "user": {"_id": str(user_id), "name": req.name, "email": req.email, "role": req.role}}

@app.post("/auth/login")
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "employee")})
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    return {"token": token, "user": user}

# Visitor creation + appointment
@app.post("/appointments")
def create_appointment(req: AppointmentCreateRequest, user=Depends(require_roles("employee", "admin"))):
    # Ensure or create visitor
    visitor_doc = db["visitor"].find_one({"email": req.visitor_email}) if req.visitor_email else None
    if not visitor_doc:
        visitor = Visitor(
            first_name=req.visitor_first_name,
            last_name=req.visitor_last_name,
            email=req.visitor_email,
            phone=req.visitor_phone,
        )
        visitor_id = db["visitor"].insert_one(visitor.model_dump()).inserted_id
    else:
        visitor_id = visitor_doc["_id"]

    appt = Appointment(
        host_user_id=req.host_user_id,
        visitor_id=str(visitor_id),
        purpose=req.purpose,
        scheduled_at=req.scheduled_at,
    )
    appt_id = db["appointment"].insert_one(appt.model_dump()).inserted_id
    return {"appointment_id": str(appt_id), "visitor_id": str(visitor_id)}

# Issue pass with QR + PDF
@app.post("/passes/issue/{appointment_id}")
def issue_pass(appointment_id: str, user=Depends(require_roles("security", "admin"))):
    appt = db["appointment"].find_one({"_id": ObjectId(appointment_id)})
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment not found")

    code = str(ObjectId())
    now = datetime.now(timezone.utc)
    valid_to = now + timedelta(hours=8)
    p = PassModel(
        appointment_id=appointment_id,
        visitor_id=appt["visitor_id"],
        code=code,
        valid_from=now,
        valid_to=valid_to,
    )
    pass_id = db["passmodel"].insert_one(p.model_dump()).inserted_id

    # Generate QR (data contains code)
    qr_img = qrcode.make(code)
    qr_bytes = BytesIO()
    qr_img.save(qr_bytes, format="PNG")
    qr_bytes.seek(0)

    # Create simple PDF badge
    pdf_bytes = BytesIO()
    c = canvas.Canvas(pdf_bytes, pagesize=letter)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, 720, "Visitor Pass")
    c.setFont("Helvetica", 12)
    c.drawString(72, 690, f"Appointment: {appointment_id}")
    c.drawString(72, 670, f"Valid: {now.strftime('%Y-%m-%d %H:%M')} - {valid_to.strftime('%Y-%m-%d %H:%M')}")
    c.drawString(72, 650, f"Code: {code}")
    c.drawImage(ImageReader(qr_bytes), 72, 520, width=160, height=160)
    c.showPage()
    c.save()
    pdf_bytes.seek(0)

    # Return metadata + base64 of PDF for demo purposes
    import base64
    pdf_b64 = base64.b64encode(pdf_bytes.read()).decode("utf-8")

    return {"pass_id": str(pass_id), "code": code, "pdf_base64": pdf_b64}

# Verify / check-in / check-out via code
class VerifyRequest(BaseModel):
    code: str

@app.post("/passes/verify")
def verify_pass(req: VerifyRequest, user=Depends(require_roles("security", "admin"))):
    p = db["passmodel"].find_one({"code": req.code})
    if not p:
        raise HTTPException(status_code=404, detail="Pass not found")
    now = datetime.now(timezone.utc)
    if now > p.get("valid_to", now):
        db["passmodel"].update_one({"_id": p["_id"]}, {"$set": {"status": "expired"}})
        raise HTTPException(status_code=400, detail="Pass expired")
    return {"pass_id": str(p["_id"]), "status": p.get("status", "issued")}

class ScanRequest(BaseModel):
    code: str
    action: str  # "check-in" | "check-out"

@app.post("/passes/scan")
def scan_pass(req: ScanRequest, user=Depends(require_roles("security", "admin"))):
    p = db["passmodel"].find_one({"code": req.code})
    if not p:
        raise HTTPException(status_code=404, detail="Pass not found")
    now = datetime.now(timezone.utc)
    if now > p.get("valid_to", now):
        db["passmodel"].update_one({"_id": p["_id"]}, {"$set": {"status": "expired"}})
        raise HTTPException(status_code=400, detail="Pass expired")

    new_status = "checked-in" if req.action == "check-in" else "checked-out"
    db["passmodel"].update_one({"_id": p["_id"]}, {"$set": {"status": new_status}})

    log = CheckLog(pass_id=str(p["_id"]), action=req.action, by_user_id=str(user["_id"]))
    db["checklog"].insert_one(log.model_dump())

    return {"pass_id": str(p["_id"]), "status": new_status}

# Simple list endpoints for dashboard
@app.get("/dashboard/stats")
def dashboard_stats(user=Depends(require_roles("admin", "security", "employee"))):
    total_visitors = db["visitor"].count_documents({})
    total_appointments = db["appointment"].count_documents({})
    active_passes = db["passmodel"].count_documents({"status": {"$in": ["issued", "checked-in"]}})
    today = datetime.now(timezone.utc).date()
    today_logs = db["checklog"].count_documents({})
    return {
        "visitors": total_visitors,
        "appointments": total_appointments,
        "active_passes": active_passes,
        "logs_today": today_logs,
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
