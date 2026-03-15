from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
import gridfs
from dotenv import load_dotenv
import bcrypt, jwt, uuid, os, re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from bson import ObjectId

load_dotenv()

MONGO_URL  = os.getenv("MONGO_URL")
DB_NAME    = os.getenv("DB_NAME")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM  = "HS256"
ACCESS_EXP  = 1440
REFRESH_EXP = 14

# Max file size: 10 MB per file, max 5 files per section
MAX_FILE_SIZE  = 10 * 1024 * 1024   # 10 MB
MAX_FILES      = 5
ALLOWED_TYPES  = {
    "image/jpeg", "image/jpg", "image/png", "image/webp", "image/heic",
    "application/pdf"
}

client      = MongoClient(MONGO_URL)
db          = client[DB_NAME]
fs          = gridfs.GridFS(db)          # GridFS for file storage
users       = db["users"]
submissions = db["submissions"]
temp_submissions = db["temp_submissions"]
admin_col   = db["admin"]

# ── Indexes ─────────────────────────────────────────────────
users.create_index("email",   unique=True)
users.create_index("user_id", unique=True)

try:
    submissions.drop_index("submission_id_1")
except Exception:
    pass

submissions.create_index([("employee_id", 1), ("date", 1)], unique=True)
submissions.create_index("submitted_at")

try:
    temp_submissions.drop_index("submission_id_1")
except Exception:
    pass
temp_submissions.create_index([("employee_id", 1), ("date", 1)], unique=True)
temp_submissions.create_index("updated_at")

# File metadata collection (lightweight — just references, not binaries)
file_meta = db["file_meta"]
file_meta.create_index("upload_id", unique=True)
file_meta.create_index("employee_id")
file_meta.create_index("date")

if not admin_col.find_one({"_id": "config"}):
    admin_col.insert_one({"_id": "config", "admin_emails": []})

app = FastAPI(title="Tree Plantation", docs_url="/api/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer()


# ── Pydantic Models ──────────────────────────────────────────
class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("name")
    @classmethod
    def check_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError("Name must be at least 2 characters")
        return v.strip()

    @field_validator("password")
    @classmethod
    def check_pw(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"\d", v):
            raise ValueError("Must contain a number")
        return v

    @field_validator("confirm_password")
    @classmethod
    def check_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class SectionSyncIn(BaseModel):
    date: str
    sections: dict


class SubmitIn(BaseModel):
    date: str


class AddAdminIn(BaseModel):
    email: EmailStr


# ── Helpers ──────────────────────────────────────────────────
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_pw(pw, h):
    return bcrypt.checkpw(pw.encode(), h.encode())

def make_access(uid, role):
    return jwt.encode(
        {"sub": uid, "role": role, "type": "access",
         "exp": datetime.utcnow() + timedelta(minutes=ACCESS_EXP)},
        JWT_SECRET, ALGORITHM
    )

def make_refresh(uid):
    return jwt.encode(
        {"sub": uid, "type": "refresh",
         "exp": datetime.utcnow() + timedelta(days=REFRESH_EXP)},
        JWT_SECRET, ALGORITHM
    )

def decode(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def get_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    p = decode(creds.credentials)
    if p.get("type") != "access":
        raise HTTPException(401, "Bad token type")
    u = users.find_one({"user_id": p["sub"]})
    if not u or not u.get("is_active"):
        raise HTTPException(401, "User not found")
    return u

def is_admin(email: str) -> bool:
    cfg = admin_col.find_one({"_id": "config"})
    if not cfg:
        return False
    return email.lower() in [e.lower() for e in cfg.get("admin_emails", [])]

def clean(d):
    if d:
        d.pop("_id", None)
    return d

def tok(uid, role, name, email):
    admin = is_admin(email)
    return {
        "access_token":  make_access(uid, role),
        "refresh_token": make_refresh(uid),
        "token_type":    "bearer",
        "user": {
            "user_id": uid,
            "name":    name,
            "email":   email,
            "role":    role,
            "is_admin": admin,
        }
    }


# ── Auth ─────────────────────────────────────────────────────
@app.post("/api/register", status_code=201)
def register(data: RegisterIn):
    uid = str(uuid.uuid4())
    try:
        users.insert_one({
            "user_id":       uid,
            "name":          data.name,
            "email":         data.email.lower(),
            "password_hash": hash_pw(data.password),
            "role":          "employee",
            "is_active":     True,
            "created_at":    datetime.utcnow().isoformat()
        })
    except DuplicateKeyError:
        raise HTTPException(409, "Email already registered")
    return tok(uid, "employee", data.name, data.email.lower())


@app.post("/api/login")
def login(data: LoginIn):
    u = users.find_one({"email": data.email.lower()})
    if not u or not verify_pw(data.password, u["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if not u.get("is_active"):
        raise HTTPException(403, "Account disabled")
    return tok(u["user_id"], u["role"], u["name"], u["email"])


@app.post("/api/refresh")
def refresh(data: RefreshIn):
    p = decode(data.refresh_token)
    if p.get("type") != "refresh":
        raise HTTPException(401, "Bad token type")
    u = users.find_one({"user_id": p["sub"]})
    if not u or not u.get("is_active"):
        raise HTTPException(401, "Not found")
    return {"access_token": make_access(u["user_id"], u["role"]), "token_type": "bearer"}


@app.get("/api/me")
def me(u=Depends(get_user)):
    return {
        "user_id":  u["user_id"],
        "name":     u["name"],
        "email":    u["email"],
        "role":     u["role"],
        "is_admin": is_admin(u["email"])
    }


# ── FILE UPLOAD (Section L) ───────────────────────────────────
@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    date: str = Form(...),
    u=Depends(get_user)
):
    """
    Upload a single file to GridFS.
    Returns a lightweight metadata record (upload_id, filename, size, content_type).
    The binary is in GridFS — section data only stores the upload_id reference.
    This keeps admin/history queries fast (no binary data in submissions).
    """
    # Validate content type
    ct = file.content_type or ""
    if ct not in ALLOWED_TYPES:
        raise HTTPException(400, f"File type '{ct}' not allowed. Use JPEG, PNG, WEBP, HEIC, or PDF.")

    # Read and validate size
    data = await file.read()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum size is 10 MB.")

    # Store binary in GridFS
    gridfs_id = fs.put(
        data,
        filename=file.filename,
        content_type=ct,
        employee_id=u["user_id"],
        date=date,
        uploaded_at=datetime.utcnow().isoformat()
    )

    # Store lightweight metadata separately
    upload_id = str(uuid.uuid4())
    meta = {
        "upload_id":   upload_id,
        "gridfs_id":   str(gridfs_id),
        "filename":    file.filename,
        "content_type": ct,
        "size":        len(data),
        "employee_id": u["user_id"],
        "employee_name": u["name"],
        "date":        date,
        "uploaded_at": datetime.utcnow().isoformat(),
    }
    file_meta.insert_one(meta)

    return {
        "upload_id":    upload_id,
        "filename":     file.filename,
        "content_type": ct,
        "size":         len(data),
    }


@app.delete("/api/files/{upload_id}")
def delete_file(upload_id: str, u=Depends(get_user)):
    """Delete a file (owner or admin only)."""
    meta = file_meta.find_one({"upload_id": upload_id})
    if not meta:
        raise HTTPException(404, "File not found")
    if meta["employee_id"] != u["user_id"] and not is_admin(u["email"]):
        raise HTTPException(403, "Not authorized")

    # Remove from GridFS
    try:
        fs.delete(ObjectId(meta["gridfs_id"]))
    except Exception:
        pass

    file_meta.delete_one({"upload_id": upload_id})
    return {"ok": True}


@app.get("/api/files/{upload_id}")
def get_file(upload_id: str, u=Depends(get_user)):
    """
    Stream file bytes from GridFS.
    Only the file owner or an admin can access it.
    """
    meta = file_meta.find_one({"upload_id": upload_id})
    if not meta:
        raise HTTPException(404, "File not found")
    if meta["employee_id"] != u["user_id"] and not is_admin(u["email"]):
        raise HTTPException(403, "Not authorized")

    try:
        grid_out = fs.get(ObjectId(meta["gridfs_id"]))
    except Exception:
        raise HTTPException(404, "File data not found")

    return StreamingResponse(
        grid_out,
        media_type=meta["content_type"],
        headers={
            "Content-Disposition": f'inline; filename="{meta["filename"]}"',
            "Content-Length": str(meta["size"]),
            "Cache-Control": "private, max-age=3600",
        }
    )


@app.get("/api/files/meta/by-date")
def get_files_by_date(date: str, u=Depends(get_user)):
    """Return file metadata list for a specific employee+date (no binaries)."""
    docs = list(file_meta.find(
        {"employee_id": u["user_id"], "date": date},
        {"_id": 0, "gridfs_id": 0}   # exclude heavy fields
    ))
    return docs


@app.get("/api/admin/files/{employee_id}")
def admin_get_files(employee_id: str, u=Depends(get_user)):
    """Admin: get all file metadata for an employee (no binaries)."""
    if not is_admin(u["email"]):
        raise HTTPException(403, "Admin access required")
    docs = list(file_meta.find(
        {"employee_id": employee_id},
        {"_id": 0, "gridfs_id": 0}
    ))
    return docs


# ── TEMP Submissions ─────────────────────────────────────────
@app.post("/api/submissions/sync")
def sync_sections(data: SectionSyncIn, u=Depends(get_user)):
    now = datetime.utcnow().isoformat()
    set_patch = {"updated_at": now, "employee_name": u["name"], "status": "draft"}
    for sec_id, sec_data in data.sections.items():
        set_patch[f"sections.{sec_id}"] = sec_data

    doc = temp_submissions.find_one_and_update(
        {"employee_id": u["user_id"], "date": data.date},
        {
            "$set": set_patch,
            "$setOnInsert": {
                "employee_id": u["user_id"],
                "date":        data.date,
                "created_at":  now,
            }
        },
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return clean(doc)


@app.get("/api/submissions/temp/today")
def get_temp_today(date: str, u=Depends(get_user)):
    doc = temp_submissions.find_one({"employee_id": u["user_id"], "date": date})
    return clean(doc) if doc else None


@app.post("/api/submissions/submit")
def submit_day(data: SubmitIn, u=Depends(get_user)):
    temp = temp_submissions.find_one({"employee_id": u["user_id"], "date": data.date})
    if not temp:
        raise HTTPException(404, "No draft found for this date. Fill at least one section first.")

    now = datetime.utcnow().isoformat()
    sections = temp.get("sections", {})
    employee_name = temp.get("employee_name", u["name"])

    doc = submissions.find_one_and_update(
        {"employee_id": u["user_id"], "date": data.date},
        {
            "$set": {
                "sections":      sections,
                "employee_name": employee_name,
                "updated_at":    now,
                "status":        "submitted",
            },
            "$setOnInsert": {
                "employee_id":  u["user_id"],
                "date":         data.date,
                "created_at":   now,
                "submitted_at": now,
            }
        },
        upsert=True,
        return_document=ReturnDocument.AFTER
    )

    temp_submissions.delete_one({"employee_id": u["user_id"], "date": data.date})
    return clean(doc)


# ── Main Submissions ─────────────────────────────────────────
@app.get("/api/submissions")
def list_submissions(u=Depends(get_user)):
    docs = list(submissions.find(
        {"employee_id": u["user_id"]},
        sort=[("date", -1)]
    ))
    return [clean(d) for d in docs]


@app.get("/api/submissions/today")
def get_today(date: str, u=Depends(get_user)):
    doc = submissions.find_one({"employee_id": u["user_id"], "date": date})
    return clean(doc) if doc else None


@app.post("/api/submissions")
def upsert_submission_legacy(data: SectionSyncIn, u=Depends(get_user)):
    return sync_sections(data, u)


# ── Admin ────────────────────────────────────────────────────
def require_admin(u=Depends(get_user)):
    if not is_admin(u["email"]):
        raise HTTPException(403, "Admin access required")
    return u


@app.get("/api/admin/employees")
def admin_list_employees(u=Depends(require_admin)):
    pipeline = [
        {"$group": {
            "_id":              "$employee_id",
            "employee_name":    {"$first": "$employee_name"},
            "submission_count": {"$sum": 1},
            "last_date":        {"$max": "$date"},
        }},
        {"$sort": {"employee_name": 1}}
    ]
    results = list(submissions.aggregate(pipeline))
    out = []
    for r in results:
        out.append({
            "employee_id":      r["_id"],
            "employee_name":    r.get("employee_name", "Unknown"),
            "submission_count": r["submission_count"],
            "last_date":        r["last_date"],
        })
    return out


@app.get("/api/admin/employee/{employee_id}")
def admin_get_employee(employee_id: str, u=Depends(require_admin)):
    docs = list(submissions.find(
        {"employee_id": employee_id},
        sort=[("date", -1)]
    ))
    return [clean(d) for d in docs]


@app.get("/api/admin/all-submissions")
def admin_all_submissions(u=Depends(require_admin)):
    docs = list(submissions.find({}, sort=[("employee_name", 1), ("date", -1)]))
    return [clean(d) for d in docs]


@app.post("/api/admin/add-admin")
def add_admin(data: AddAdminIn, u=Depends(require_admin)):
    admin_col.update_one(
        {"_id": "config"},
        {"$addToSet": {"admin_emails": data.email.lower()}}
    )
    return {"ok": True, "message": f"{data.email} added as admin"}


@app.get("/api/admin/list-admins")
def list_admins(u=Depends(require_admin)):
    cfg = admin_col.find_one({"_id": "config"})
    return {"admin_emails": cfg.get("admin_emails", []) if cfg else []}


@app.post("/api/admin/bootstrap")
def bootstrap_admin(email: str):
    admin_col.update_one(
        {"_id": "config"},
        {"$addToSet": {"admin_emails": email.lower()}}
    )
    return {"ok": True, "message": f"{email} bootstrapped as admin"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ── Static ────────────────────────────────────────────────────
STATIC = Path(__file__).parent / "static"
if STATIC.is_dir():
    @app.get("/sw.js", include_in_schema=False)
    def sw():
        return FileResponse(
            str(STATIC / "sw.js"),
            headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"}
        )

    @app.get("/manifest.json", include_in_schema=False)
    def manifest():
        return FileResponse(str(STATIC / "manifest.json"))

    app.mount("/icons", StaticFiles(directory=str(STATIC / "icons")), name="icons")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(str(STATIC / "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = STATIC / path
        return FileResponse(str(f) if f.is_file() else str(STATIC / "index.html"))