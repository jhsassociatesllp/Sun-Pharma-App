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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

load_dotenv()
MONGO_URL  = os.getenv("MONGO_URL")
DB_NAME    = os.getenv("DB_NAME")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM  = "HS256"
ACCESS_EXP  = 1440
REFRESH_EXP = 14

client           = MongoClient(MONGO_URL)
db               = client[DB_NAME]
users            = db["users"]
submissions      = db["submissions"]
temp_submissions = db["temp_submissions"]
admin_col        = db["admin"]
excel_data       = db["excel_data"]

users.create_index("email", unique=True)
users.create_index("user_id", unique=True)

# Drop old unique constraints that conflict with multi-form
for idx in ["employee_id_1_date_1", "submission_id_1"]:
    try: submissions.drop_index(idx)
    except: pass
for idx in ["employee_id_1_date_1", "submission_id_1", "form_id_1"]:
    try: temp_submissions.drop_index(idx)
    except: pass

# Remove old-architecture temp docs that have no form_id
# (they would cause E11000 duplicate key errors on the new unique sparse index)
temp_submissions.delete_many({"form_id": {"$in": [None, ""]}})

# New: unique per form_id — sparse=True skips docs without form_id
submissions.create_index("submission_id", unique=True, sparse=True)
submissions.create_index([("employee_id", 1), ("date", -1)])
temp_submissions.create_index("form_id", unique=True, sparse=True)
temp_submissions.create_index([("employee_id", 1), ("date", -1)])

if not admin_col.find_one({"_id": "config"}):
    admin_col.insert_one({"_id": "config", "admin_emails": []})

app = FastAPI(title="Tree Plantation", docs_url="/api/docs")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer()

class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str
    @field_validator("name")
    @classmethod
    def check_name(cls, v):
        if len(v.strip()) < 2: raise ValueError("Name must be at least 2 characters")
        return v.strip()
    @field_validator("password")
    @classmethod
    def check_pw(cls, v):
        if len(v) < 8: raise ValueError("Password must be at least 8 characters")
        if not re.search(r"\d", v): raise ValueError("Must contain a number")
        return v
    @field_validator("confirm_password")
    @classmethod
    def check_match(cls, v, info):
        if "password" in info.data and v != info.data["password"]: raise ValueError("Passwords do not match")
        return v

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class RefreshIn(BaseModel):
    refresh_token: str

class FormSyncIn(BaseModel):
    form_id: str
    date: str
    sections: dict
    form_number: Optional[int] = 1

class FormSubmitIn(BaseModel):
    form_id: str
    date: str

class AddAdminIn(BaseModel):
    email: EmailStr

def hash_pw(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def verify_pw(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())
def make_access(uid, role):
    return jwt.encode({"sub": uid, "role": role, "type": "access",
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_EXP)}, JWT_SECRET, ALGORITHM)
def make_refresh(uid):
    return jwt.encode({"sub": uid, "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_EXP)}, JWT_SECRET, ALGORITHM)
def decode(token):
    try: return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError: raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError: raise HTTPException(401, "Invalid token")
def get_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    p = decode(creds.credentials)
    if p.get("type") != "access": raise HTTPException(401, "Bad token type")
    u = users.find_one({"user_id": p["sub"]})
    if not u or not u.get("is_active"): raise HTTPException(401, "User not found")
    return u
def is_admin(email):
    cfg = admin_col.find_one({"_id": "config"})
    return email.lower() in [e.lower() for e in (cfg or {}).get("admin_emails", [])]
def clean(d):
    if d: d.pop("_id", None)
    return d
def tok(uid, role, name, email):
    return {"access_token": make_access(uid, role), "refresh_token": make_refresh(uid),
        "token_type": "bearer", "user": {"user_id": uid, "name": name, "email": email,
        "role": role, "is_admin": is_admin(email)}}

@app.post("/api/register", status_code=201)
def register(data: RegisterIn):
    uid = str(uuid.uuid4())
    try:
        users.insert_one({"user_id": uid, "name": data.name, "email": data.email.lower(),
            "password_hash": hash_pw(data.password), "role": "employee", "is_active": True,
            "created_at": datetime.utcnow().isoformat()})
    except DuplicateKeyError: raise HTTPException(409, "Email already registered")
    return tok(uid, "employee", data.name, data.email.lower())

@app.post("/api/login")
def login(data: LoginIn):
    u = users.find_one({"email": data.email.lower()})
    if not u or not verify_pw(data.password, u["password_hash"]): raise HTTPException(401, "Invalid email or password")
    if not u.get("is_active"): raise HTTPException(403, "Account disabled")
    return tok(u["user_id"], u["role"], u["name"], u["email"])

@app.post("/api/refresh")
def refresh(data: RefreshIn):
    p = decode(data.refresh_token)
    if p.get("type") != "refresh": raise HTTPException(401, "Bad token type")
    u = users.find_one({"user_id": p["sub"]})
    if not u or not u.get("is_active"): raise HTTPException(401, "Not found")
    return {"access_token": make_access(u["user_id"], u["role"]), "token_type": "bearer"}

@app.get("/api/me")
def me(u=Depends(get_user)):
    return {"user_id": u["user_id"], "name": u["name"], "email": u["email"],
        "role": u["role"], "is_admin": is_admin(u["email"])}

# ── Multi-form endpoints ─────────────────────────────────────
@app.post("/api/forms/sync")
def sync_form(data: FormSyncIn, u=Depends(get_user)):
    """Upsert one form's sections into TEMP by form_id."""
    now = datetime.utcnow().isoformat()
    set_patch = {"updated_at": now, "employee_name": u["name"], "employee_id": u["user_id"],
        "date": data.date, "status": "draft", "form_number": data.form_number}
    for sec_id, sec_data in data.sections.items():
        set_patch[f"sections.{sec_id}"] = sec_data
    doc = temp_submissions.find_one_and_update(
        {"form_id": data.form_id},
        {"$set": set_patch, "$setOnInsert": {"form_id": data.form_id, "created_at": now}},
        upsert=True, return_document=ReturnDocument.AFTER)
    return clean(doc)

@app.get("/api/forms/today")
def get_forms_today(date: str, u=Depends(get_user)):
    """Return all draft forms for today."""
    docs = list(temp_submissions.find({"employee_id": u["user_id"], "date": date}, sort=[("form_number", 1)]))
    return [clean(d) for d in docs]

@app.post("/api/forms/submit")
def submit_form(data: FormSubmitIn, u=Depends(get_user)):
    """Move one form from TEMP → main submissions."""
    temp = temp_submissions.find_one({"form_id": data.form_id, "employee_id": u["user_id"]})
    if not temp: raise HTTPException(404, "Draft form not found.")
    now = datetime.utcnow().isoformat()
    sid = str(uuid.uuid4())
    doc = {"submission_id": sid, "form_id": data.form_id, "employee_id": u["user_id"],
        "employee_name": temp.get("employee_name", u["name"]), "date": data.date,
        "form_number": temp.get("form_number", 1), "sections": temp.get("sections", {}),
        "status": "submitted", "created_at": temp.get("created_at", now),
        "submitted_at": now, "updated_at": now}
    submissions.insert_one(doc)
    temp_submissions.delete_one({"form_id": data.form_id})
    return clean(doc)

@app.delete("/api/forms/draft/{form_id}")
def delete_draft(form_id: str, u=Depends(get_user)):
    r = temp_submissions.delete_one({"form_id": form_id, "employee_id": u["user_id"]})
    if r.deleted_count == 0: raise HTTPException(404, "Draft not found")
    return {"ok": True}

@app.get("/api/submissions")
def list_submissions(u=Depends(get_user)):
    docs = list(submissions.find({"employee_id": u["user_id"]}, sort=[("date", -1), ("form_number", 1)]))
    return [clean(d) for d in docs]

# ── Legacy endpoints (backwards compat) ─────────────────────
@app.post("/api/submissions/sync")
async def legacy_sync(request: Request, u=Depends(get_user)):
    body = await request.json()
    fid = body.get("form_id") or str(uuid.uuid4())
    return sync_form(FormSyncIn(form_id=fid, date=body.get("date",""), sections=body.get("sections",{}), form_number=1), u)

@app.get("/api/submissions/temp/today")
def legacy_temp_today(date: str, u=Depends(get_user)):
    docs = list(temp_submissions.find({"employee_id": u["user_id"], "date": date}, sort=[("form_number",1)]))
    return clean(docs[0]) if docs else None

@app.post("/api/submissions/submit")
async def legacy_submit(request: Request, u=Depends(get_user)):
    body = await request.json()
    date = body.get("date","")
    temp = temp_submissions.find_one({"employee_id": u["user_id"], "date": date})
    if not temp: raise HTTPException(404, "No draft found.")
    return submit_form(FormSubmitIn(form_id=temp["form_id"], date=date), u)

def require_admin(u=Depends(get_user)):
    if not is_admin(u["email"]): raise HTTPException(403, "Admin access required")
    return u

@app.get("/api/admin/employees")
def admin_list_employees(u=Depends(require_admin)):
    pipeline = [{"$group": {"_id": "$employee_id", "employee_name": {"$first": "$employee_name"},
        "submission_count": {"$sum": 1}, "last_date": {"$max": "$date"}}}, {"$sort": {"employee_name": 1}}]
    return [{"employee_id": r["_id"], "employee_name": r.get("employee_name","Unknown"),
        "submission_count": r["submission_count"], "last_date": r["last_date"]}
        for r in submissions.aggregate(pipeline)]

@app.get("/api/admin/employee/{employee_id}")
def admin_get_employee(employee_id: str, u=Depends(require_admin)):
    docs = list(submissions.find({"employee_id": employee_id}, sort=[("date",-1),("form_number",1)]))
    return [clean(d) for d in docs]

@app.get("/api/admin/all-submissions")
def admin_all_submissions(u=Depends(require_admin)):
    docs = list(submissions.find({}, sort=[("employee_name",1),("date",-1),("form_number",1)]))
    return [clean(d) for d in docs]

@app.post("/api/admin/add-admin")
def add_admin(data: AddAdminIn, u=Depends(require_admin)):
    admin_col.update_one({"_id":"config"},{"$addToSet":{"admin_emails":data.email.lower()}})
    return {"ok": True}

@app.get("/api/admin/list-admins")
def list_admins(u=Depends(require_admin)):
    cfg = admin_col.find_one({"_id":"config"})
    return {"admin_emails": (cfg or {}).get("admin_emails",[])}

@app.post("/api/admin/bootstrap")
def bootstrap_admin(email: str):
    admin_col.update_one({"_id":"config"},{"$addToSet":{"admin_emails":email.lower()}})
    return {"ok": True}

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.get("/api/debug/collections")
def debug_collections(u=Depends(require_admin)):
    return {"collections": db.list_collection_names(),
        "excel_data_count": excel_data.count_documents({}),
        "submissions_count": submissions.count_documents({}),
        "temp_count": temp_submissions.count_documents({})}

@app.post("/api/admin/excel-upload", status_code=201)
async def admin_upload_excel(request: Request, u=Depends(require_admin)):
    data = await request.json()
    if not data or not isinstance(data, list): raise HTTPException(400, "No data provided")
    excel_data.delete_many({})
    now = datetime.utcnow().isoformat()
    docs = []
    for i, row in enumerate(data):
        doc = {str(k).strip().lower().replace(' ','_').replace('-','_').replace('/','_').replace('.','_'):
            (str(v) if v is not None else '') for k,v in row.items()}
        doc["upload_date"] = now; doc["row_index"] = i
        docs.append(doc)
    if docs: excel_data.insert_many(docs)
    return {"ok": True, "message": f"Uploaded {len(docs)} records successfully"}

@app.get("/api/admin/excel-data")
def admin_get_excel_data(u=Depends(require_admin)):
    return [clean(d) for d in excel_data.find({}, sort=[("row_index",1)])]

@app.delete("/api/admin/excel-data")
def admin_clear_excel_data(u=Depends(require_admin)):
    r = excel_data.delete_many({})
    return {"ok": True, "message": f"Cleared {r.deleted_count} records"}

@app.get("/api/excel-data/search")
def search_excel_data(q: str, u=Depends(get_user)):
    if not q or len(q.strip()) < 1: return []
    query = q.strip().lower()
    matches = []
    for doc in excel_data.find({}):
        fname = doc.get("farmer_name") or doc.get("name") or doc.get("beneficiary_name") or ""
        if not fname: continue
        score = smart_sim(query, fname.strip().lower())
        if score > 0:
            dc = clean(doc); dc["match_score"] = score; matches.append(dc)
    matches.sort(key=lambda x: x["match_score"], reverse=True)
    return matches[:10]

def smart_sim(q, name):
    if q == name: return 100.0
    if name.startswith(q): return 95.0
    words = name.split()
    if any(w.startswith(q) for w in words): return 90.0
    if q in name: return 85.0
    qw = q.split()
    if len(qw)>1 and all(w in name for w in qw): return 80.0
    best = 0.0
    for nw in words:
        for w in qw:
            if len(w)<2 or abs(len(nw)-len(w))>max(len(w)//2,2): continue
            d = lev(w,nw); ml = max(len(w),len(nw))
            s = ((ml-d)/ml)*75
            if s>best: best=s
    return best if best>=50 else 0.0

def lev(a,b):
    if a==b: return 0
    if not a: return len(b)
    if not b: return len(a)
    p=list(range(len(b)+1))
    for i,ca in enumerate(a):
        c=[i+1]
        for j,cb in enumerate(b): c.append(min(p[j+1]+1,c[j]+1,p[j]+(0 if ca==cb else 1)))
        p=c
    return p[len(b)]

STATIC = Path(__file__).parent / "static"
if STATIC.is_dir():
    @app.get("/sw.js", include_in_schema=False)
    def sw(): return FileResponse(str(STATIC/"sw.js"), headers={"Cache-Control":"no-cache","Service-Worker-Allowed":"/"})
    @app.get("/manifest.json", include_in_schema=False)
    def manifest(): return FileResponse(str(STATIC/"manifest.json"))
    app.mount("/icons", StaticFiles(directory=str(STATIC/"icons")), name="icons")
    @app.get("/", include_in_schema=False)
    def index(): return FileResponse(str(STATIC/"index.html"))
    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = STATIC/path
        return FileResponse(str(f) if f.is_file() else str(STATIC/"index.html"))