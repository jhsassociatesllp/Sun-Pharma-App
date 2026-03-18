from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
import bcrypt, jwt, uuid, os, re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

load_dotenv()

MONGO_URL  = os.getenv("MONGO_URL")
DB_NAME    = os.getenv("DB_NAME")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM  = "HS256"
ACCESS_EXP  = 1440
REFRESH_EXP = 14

client      = MongoClient(MONGO_URL)
db          = client[DB_NAME]
users       = db["users"]
submissions = db["submissions"]        # ── MAIN (submitted) collection
temp_submissions = db["temp_submissions"]  # ── TEMP (in-progress) collection
admin_col   = db["admin"]
excel_data  = db["excel_data"]         # ── Excel uploaded data collection

# ── Indexes ─────────────────────────────────────────────────
users.create_index("email",   unique=True)
users.create_index("user_id", unique=True)

try:
    submissions.drop_index("submission_id_1")
except Exception:
    pass

# Main submissions: unique per employee+date
submissions.create_index([("employee_id", 1), ("date", 1)], unique=True)
submissions.create_index("submitted_at")

# Temp submissions: unique per employee+date (only one in-progress per day)
try:
    temp_submissions.drop_index("submission_id_1")
except Exception:
    pass
temp_submissions.create_index([("employee_id", 1), ("date", 1)], unique=True)
temp_submissions.create_index("updated_at")

# Admin config
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
    date: str       # "YYYY-MM-DD"
    sections: dict  # { "A": {...}, "B": {...} }


class SubmitIn(BaseModel):
    date: str       # "YYYY-MM-DD" — finalize this day's temp data


class AddAdminIn(BaseModel):
    email: EmailStr


class ExcelUploadIn(BaseModel):
    sr_no: Optional[str] = None
    booking_id: Optional[str] = None
    farmer_name: Optional[str] = None
    district: Optional[str] = None
    taluka: Optional[str] = None
    village: Optional[str] = None
    farmer_contact: Optional[str] = None
    crop_name: Optional[str] = None
    acre: Optional[str] = None
    plantation_type: Optional[str] = None
    delivery_date: Optional[str] = None
    plantation_quantity: Optional[str] = None
    sericulture: Optional[str] = None
    technical_verification: Optional[str] = None
    accounts_verification: Optional[str] = None
    gender: Optional[str] = None


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


# ── TEMP Submissions (in-progress, saved but not submitted) ──
@app.post("/api/submissions/sync")
def sync_sections(data: SectionSyncIn, u=Depends(get_user)):
    """
    Upsert sections into the TEMP collection.
    Called automatically as the user fills sections (online).
    Does NOT move data to the main submissions collection.
    """
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
    """Return today's temp (draft) doc if it exists."""
    doc = temp_submissions.find_one({"employee_id": u["user_id"], "date": date})
    return clean(doc) if doc else None


@app.post("/api/submissions/submit")
def submit_day(data: SubmitIn, u=Depends(get_user)):
    """
    Move today's temp data into the MAIN submissions collection.
    Clears the temp record afterward.
    """
    temp = temp_submissions.find_one({"employee_id": u["user_id"], "date": data.date})
    if not temp:
        raise HTTPException(404, "No draft found for this date. Fill at least one section first.")

    now = datetime.utcnow().isoformat()
    sections = temp.get("sections", {})
    employee_name = temp.get("employee_name", u["name"])

    # Upsert into main collection
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

    # Delete from temp
    temp_submissions.delete_one({"employee_id": u["user_id"], "date": data.date})

    return clean(doc)


# ── Main Submissions (submitted / finalized) ─────────────────
@app.get("/api/submissions")
def list_submissions(u=Depends(get_user)):
    """List all SUBMITTED (finalized) submissions for the current user."""
    docs = list(submissions.find(
        {"employee_id": u["user_id"]},
        sort=[("date", -1)]
    ))
    return [clean(d) for d in docs]


@app.get("/api/submissions/today")
def get_today(date: str, u=Depends(get_user)):
    """Check if today has already been submitted (finalized)."""
    doc = submissions.find_one({"employee_id": u["user_id"], "date": date})
    return clean(doc) if doc else None


# ── Legacy sync endpoint (keep for backwards compat) ─────────
@app.post("/api/submissions")
def upsert_submission_legacy(data: SectionSyncIn, u=Depends(get_user)):
    """Backwards-compat: routes to sync endpoint."""
    return sync_sections(data, u)


# ── Admin endpoints ──────────────────────────────────────────
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


@app.get("/api/debug/collections")
def debug_collections(u=Depends(require_admin)):
    """Debug endpoint to check database collections."""
    print(f"DEBUG: Checking collections for user: {u['email']}")

    # Check if collections exist
    collections = db.list_collection_names()
    print(f"DEBUG: Available collections: {collections}")

    # Check counts
    excel_count = excel_data.count_documents({})
    users_count = users.count_documents({})
    submissions_count = submissions.count_documents({})

    print(f"DEBUG: Excel data count: {excel_count}")
    print(f"DEBUG: Users count: {users_count}")
    print(f"DEBUG: Submissions count: {submissions_count}")

    return {
        "collections": collections,
        "excel_data_count": excel_count,
        "users_count": users_count,
        "submissions_count": submissions_count,
        "excel_sample": list(excel_data.find({}).limit(2)) if excel_count > 0 else []
    }


@app.post("/api/admin/excel-upload", status_code=201)
async def admin_upload_excel(request: Request, u=Depends(require_admin)):
    """Upload Excel data to database — accepts any column structure."""
    from fastapi import Request
    data = await request.json()
    
    if not data or not isinstance(data, list):
        raise HTTPException(400, "No data provided")
    
    print(f"DEBUG: Received {len(data)} rows, sample keys: {list(data[0].keys()) if data else []}")
    
    # Clear existing data
    excel_data.delete_many({})
    
    now = datetime.utcnow().isoformat()
    documents = []
    for i, row in enumerate(data):
        # Normalize keys: lowercase + underscores, keep all columns as-is
        doc = {}
        for k, v in row.items():
            # Normalize key
            norm_key = str(k).strip().lower().replace(' ', '_').replace('-', '_').replace('/', '_').replace('.', '_')
            doc[norm_key] = str(v) if v is not None else ''
        doc["upload_date"] = now
        doc["row_index"] = i
        documents.append(doc)
    
    if documents:
        excel_data.insert_many(documents)
    
    return {"ok": True, "message": f"Uploaded {len(documents)} records successfully"}
    
@app.get("/api/admin/excel-data")
def admin_get_excel_data(u=Depends(require_admin)):
    """Get all Excel data."""
    print(f"DEBUG: Getting Excel data for admin: {u['email']}")
    docs = list(excel_data.find({}, sort=[("row_index", 1)]))
    print(f"DEBUG: Found {len(docs)} Excel records")
    if docs:
        print(f"DEBUG: Sample record: {docs[0]}")
    return [clean(d) for d in docs]


@app.delete("/api/admin/excel-data")
def admin_clear_excel_data(u=Depends(require_admin)):
    """Clear all Excel data."""
    result = excel_data.delete_many({})
    return {"ok": True, "message": f"Cleared {result.deleted_count} records"}


# ─────────────────────────────────────────────────────────────
# REPLACE these two functions in main.py
# ─────────────────────────────────────────────────────────────

@app.get("/api/excel-data/search")
def search_excel_data(q: str, u=Depends(get_user)):
    """Search Excel data by farmer name — substring + fuzzy matching."""
    if not q or len(q.strip()) < 1:
        return []

    query = q.strip().lower()

    # Get all Excel data
    all_docs = list(excel_data.find({}))

    matches = []
    for doc in all_docs:
        # Support both normalized key names
        farmer_name = (
            doc.get("farmer_name") or
            doc.get("name") or
            doc.get("beneficiary_name") or ""
        )
        if not farmer_name:
            continue

        name_lower = farmer_name.strip().lower()
        score = calculate_smart_similarity(query, name_lower)

        if score > 0:
            doc_copy = clean(doc)
            doc_copy["match_score"] = score
            matches.append(doc_copy)

    # Sort: exact substring matches first, then by score
    matches.sort(key=lambda x: x["match_score"], reverse=True)
    return matches[:10]


def calculate_smart_similarity(query: str, full_name: str) -> float:
    """
    Smart name matching that handles partial name searches properly.

    Priority (highest score first):
    1. Exact full match          → 100
    2. Starts with query         → 95
    3. Any word starts with query→ 90
    4. Substring anywhere        → 85
    5. All query words found     → 80
    6. Levenshtein on each word  → 0–75
    """
    if not query or not full_name:
        return 0.0

    query = query.strip().lower()
    full_name = full_name.strip().lower()

    # 1. Exact match
    if query == full_name:
        return 100.0

    # 2. Full name starts with query
    if full_name.startswith(query):
        return 95.0

    # 3. Any individual word in full_name starts with query
    name_words = full_name.split()
    if any(w.startswith(query) for w in name_words):
        return 90.0

    # 4. Query appears anywhere as substring
    if query in full_name:
        return 85.0

    # 5. All words in query appear somewhere in full_name
    query_words = query.split()
    if len(query_words) > 1 and all(qw in full_name for qw in query_words):
        return 80.0

    # 6. Fuzzy: check each name word against each query word
    #    If any name word is fuzzy-close to any query word → partial score
    best = 0.0
    for nw in name_words:
        for qw in query_words:
            if len(qw) < 2:
                continue
            # Only run Levenshtein on similarly-lengthed words
            if abs(len(nw) - len(qw)) > max(len(qw) // 2, 2):
                continue
            dist = levenshtein(qw, nw)
            max_len = max(len(qw), len(nw))
            word_sim = ((max_len - dist) / max_len) * 75  # cap at 75
            if word_sim > best:
                best = word_sim

    return best if best >= 50 else 0.0  # only return if >= 50% word-level match


def levenshtein(s1: str, s2: str) -> int:
    """Standard Levenshtein distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,   # deletion
                curr[j] + 1,       # insertion
                prev[j] + (0 if c1 == c2 else 1)  # substitution
            ))
        prev = curr
    return prev[len(s2)]

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