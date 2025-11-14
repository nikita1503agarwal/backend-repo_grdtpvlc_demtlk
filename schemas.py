"""
Database Schemas for Visitor Pass Management System

Each Pydantic model represents a collection in MongoDB. The collection name is the
lowercase of the class name.

Collections:
- user
- visitor
- appointment
- passmodel (named PassModel to avoid Python keyword)
- checklog
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# -------------------- Users --------------------
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: Optional[str] = Field(None, description="BCrypt hash of password")
    role: Literal["admin", "security", "employee", "visitor"] = Field(
        "employee", description="Role of the user"
    )
    organization_id: Optional[str] = Field(None, description="Organization identifier for multi-org support")
    is_active: bool = Field(True, description="Whether the user is active")

# -------------------- Visitors --------------------
class Visitor(BaseModel):
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    photo_url: Optional[str] = Field(None, description="URL of uploaded photo")
    organization_id: Optional[str] = None
    notes: Optional[str] = None

# -------------------- Appointments --------------------
class Appointment(BaseModel):
    host_user_id: str = Field(..., description="User ID of host/employee")
    visitor_id: str = Field(..., description="Visitor ID")
    purpose: str
    scheduled_at: datetime
    status: Literal["pending", "approved", "rejected", "completed"] = "pending"
    organization_id: Optional[str] = None

# -------------------- Passes --------------------
class PassModel(BaseModel):
    appointment_id: str
    visitor_id: str
    code: str = Field(..., description="Unique pass code embedded in QR")
    valid_from: datetime
    valid_to: datetime
    status: Literal["issued", "checked-in", "checked-out", "expired", "revoked"] = "issued"
    organization_id: Optional[str] = None

# -------------------- Check Logs --------------------
class CheckLog(BaseModel):
    pass_id: str
    action: Literal["check-in", "check-out"]
    by_user_id: Optional[str] = None
    location: Optional[str] = None
    notes: Optional[str] = None
