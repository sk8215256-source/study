import json
import re
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint("admission", __name__)
DB_PATH = None
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EDITABLE = ("pending_review", "correction_requested")

# Admin decision rules: action -> (allowed current statuses, new status, note required)
RULES = {
    "accept": ({"pending_review"}, "accepted", False),
    "reject": ({"pending_review"}, "rejected", True),
    "request_correction": ({"pending_review", "rejected"}, "correction_requested", True),
}

SECTIONS = [
    ("Personal Details", [
        ("full_name", "Full Name", 1), ("father_name", "Father's Name", 1), ("mother_name", "Mother's Name", 1),
        ("dob", "Date of Birth", 1), ("gender", "Gender", 0), ("alt_mobile", "Alternate Mobile", 0)]),
    ("Address", [
        ("house", "House Number", 1), ("street", "Street or Locality", 1), ("village", "Village or Gram", 1),
        ("gram_panchayat", "Gram Panchayat", 0), ("po", "Post Office (PO)", 1), ("ps", "Police Station (PS)", 1),
        ("block", "Block or Municipality", 0), ("district", "District", 1), ("state", "State", 1),
        ("pin", "PIN Code", 1), ("country", "Country", 1)]),
    ("Education & Course", [
        ("education", "Current Education Level", 1), ("prev_qualification", "Previous Qualification", 0),
        ("course", "Course Name", 1), ("subject", "Subject", 0), ("batch", "Preferred Batch", 1),
        ("class_time", "Preferred Class Time", 1), ("session", "Admission Session", 1),
        ("info", "Additional Information", 0)]),
]


# ---------- Database ----------

def init_admission_db(path):
    global DB_PATH
    DB_PATH = path
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            student_code TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT NOT NULL,
            pw_hash TEXT NOT NULL,
            account_status TEXT NOT NULL DEFAULT 'active',
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT);
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY,
            app_code TEXT UNIQUE NOT NULL,
            student_id INTEGER UNIQUE NOT NULL REFERENCES students(id),
            full_name TEXT, district TEXT, course TEXT,
            data TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending_review',
            decision_note TEXT DEFAULT '',
            internal_note TEXT DEFAULT '',
            submitted TEXT DEFAULT CURRENT_TIMESTAMP,
            updated TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            actor TEXT, action TEXT, target TEXT,
            detail TEXT DEFAULT '',
            created TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    con.commit()
    con.close()


def db():
    if "adb" not in g:
        g.adb = sqlite3.connect(DB_PATH)
        g.adb.row_factory = sqlite3.Row
    return g.adb


@bp.teardown_app_request
def _close_db(_exc):
    con = g.pop("adb", None)
    if con is not None:
        con.close()


def q(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]


def run(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur


def audit(actor, action, target, detail=""):
    run("INSERT INTO audit_log (actor, action, target, detail) VALUES (?, ?, ?, ?)",
        (actor, action, target, detail))


def body():
    return (request.get_json(silent=True) if request.is_json else None) or {}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def student_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sid = session.get("student_id")
        rows = q("SELECT * FROM students WHERE id = ?", (sid,)) if sid else []
        if not rows:
            return jsonify(error="Please log in first"), 401
        if rows[0]["account_status"] != "active":
            session.pop("student_id", None)
            return jsonify(error="This account is suspended"), 403
        g.student = rows[0]
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify(error="Admin login required"), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------- Pages ----------

@bp.get("/student")
def student_page():
    return render_template("student.html")


@bp.get("/admin/admissions")
def admissions_page():
    return render_template("admissions_admin.html")


# ---------- Student accounts ----------

@bp.post("/api/student/register")
def register():
    d = body()
    name = str(d.get("full_name", "")).strip()[:100]
    email = str(d.get("email", "")).strip().lower()
    mobile = re.sub(r"[^\d+]", "", str(d.get("mobile", "")))[:20]
    password = str(d.get("password", ""))
    if not name or not EMAIL_RE.match(email) or sum(c.isdigit() for c in mobile) < 10 or len(password) < 8:
        return jsonify(error="Name, valid email, 10+ digit mobile and an 8+ character password are required"), 400
    try:
        cur = run("INSERT INTO students (student_code, full_name, email, mobile, pw_hash) VALUES (?, ?, ?, ?, ?)",
                  (f"tmp-{uuid.uuid4().hex}", name, email, mobile, generate_password_hash(password)))
    except sqlite3.IntegrityError:
        return jsonify(error="An account with this email already exists"), 409
    code = f"SP{datetime.now().year}{cur.lastrowid:05d}"
    run("UPDATE students SET student_code = ? WHERE id = ?", (code, cur.lastrowid))
    audit("student", "registered", code)
    return jsonify(ok=True, student_code=code), 201


@bp.post("/api/student/login")
def login():
    d = body()
    rows = q("SELECT * FROM students WHERE email = ?", (str(d.get("email", "")).strip().lower(),))
    if not rows or not check_password_hash(rows[0]["pw_hash"], str(d.get("password", ""))):
        return jsonify(error="Wrong email or password"), 401
    if rows[0]["account_status"] != "active":
        return jsonify(error="This account is suspended. Please contact the office."), 403
    session["student_id"] = rows[0]["id"]
    run("UPDATE students SET last_login = ? WHERE id = ?", (now(), rows[0]["id"]))
    return jsonify(ok=True)


@bp.post("/api/student/logout")
def logout():
    session.pop("student_id", None)
    return jsonify(ok=True)


@bp.get("/api/student/me")
@student_required
def me():
    s = g.student
    return jsonify(student_code=s["student_code"], full_name=s["full_name"], email=s["email"],
                   mobile=s["mobile"], last_login=s["last_login"])


@bp.put("/api/student/profile")
@student_required
def update_profile():
    d = body()
    name = str(d.get("full_name", g.student["full_name"])).strip()[:100]
    mobile = re.sub(r"[^\d+]", "", str(d.get("mobile", g.student["mobile"])))[:20]
    if not name or sum(c.isdigit() for c in mobile) < 10:
        return jsonify(error="Name and a 10+ digit mobile number are required"), 400
    run("UPDATE students SET full_name = ?, mobile = ? WHERE id = ?", (name, mobile, g.student["id"]))
    return jsonify(ok=True)


# ---------- Admission application (student) ----------

def clean_application(d):
    data, errors = {}, []
    for _, fields in SECTIONS:
        for key, label, required in fields:
            value = str(d.get(key, "") or "").strip()[:1000 if key == "info" else 200]
            if required and not value:
                errors.append(f"{label} is required")
            data[key] = value
    if data["dob"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["dob"]):
        errors.append("Date of Birth is invalid")
    if data["pin"] and not re.fullmatch(r"\d{6}", data["pin"]):
        errors.append("PIN Code must be 6 digits")
    return data, errors


def application_view(row):
    row["data"] = json.loads(row["data"])
    row["editable"] = row["status"] in EDITABLE
    return row


@bp.get("/api/admission/schema")
def schema():
    return jsonify([{
        "title": title,
        "fields": [{"key": k, "label": l, "required": bool(r),
                    "type": "date" if k == "dob" else "tel" if "mobile" in k else "text"}
                   for k, l, r in fields]
    } for title, fields in SECTIONS])


@bp.get("/api/student/application")
@student_required
def my_application():
    rows = q("SELECT app_code, status, decision_note, data, submitted, updated FROM applications WHERE student_id = ?",
             (g.student["id"],))
    return jsonify(application=application_view(rows[0]) if rows else None)


@bp.post("/api/student/application")
@student_required
def submit_application():
    data, errors = clean_application(body())
    if errors:
        return jsonify(error="; ".join(errors)), 400
    try:
        cur = run("INSERT INTO applications (app_code, student_id, full_name, district, course, data) VALUES (?, ?, ?, ?, ?, ?)",
                  (f"tmp-{uuid.uuid4().hex}", g.student["id"], data["full_name"], data["district"], data["course"],
                   json.dumps(data, ensure_ascii=False)))
    except sqlite3.IntegrityError:
        return jsonify(error="You already have an application. You can view or edit it."), 409
    code = f"APP{datetime.now().year}{cur.lastrowid:05d}"
    run("UPDATE applications SET app_code = ? WHERE id = ?", (code, cur.lastrowid))
    audit(g.student["student_code"], "application_submitted", code)
    return jsonify(ok=True, app_code=code), 201


@bp.put("/api/student/application")
@student_required
def update_application():
    rows = q("SELECT id, app_code, status FROM applications WHERE student_id = ?", (g.student["id"],))
    if not rows:
        return jsonify(error="No application yet"), 404
    if rows[0]["status"] not in EDITABLE:
        return jsonify(error="This application can no longer be edited"), 409
    data, errors = clean_application(body())
    if errors:
        return jsonify(error="; ".join(errors)), 400
    run("""UPDATE applications SET data = ?, full_name = ?, district = ?, course = ?,
           status = 'pending_review', updated = CURRENT_TIMESTAMP WHERE id = ?""",
        (json.dumps(data, ensure_ascii=False), data["full_name"], data["district"], data["course"], rows[0]["id"]))
    audit(g.student["student_code"], "application_updated", rows[0]["app_code"])
    return jsonify(ok=True)


# ---------- Admin: applications ----------

@bp.get("/api/admin/admissions")
@admin_required
def admin_list():
    rows = q("""SELECT a.id, a.app_code, a.status, a.district, a.course, a.submitted, a.data,
                       s.student_code, s.full_name, s.email, s.mobile
                FROM applications a JOIN students s ON s.id = a.student_id""")
    for r in rows:
        d = json.loads(r.pop("data"))
        r.update({k: d.get(k, "") for k in ("village", "po", "ps", "pin", "batch")})
    text = request.args.get("q", "").strip().lower()
    if text:
        rows = [r for r in rows if text in " ".join(
            str(r[k]) for k in ("full_name", "student_code", "app_code", "email", "mobile")).lower()]
    for key in ("status", "district", "course"):
        wanted = request.args.get(key, "").strip().lower()
        if wanted:
            rows = [r for r in rows if str(r.get(key) or "").lower() == wanted]
    rows.sort(key=lambda r: r["submitted"], reverse=request.args.get("sort") != "oldest")
    return jsonify(rows)


@bp.get("/api/admin/admissions/<int:aid>")
@admin_required
def admin_detail(aid):
    rows = q("""SELECT a.*, s.student_code, s.full_name AS account_name, s.email, s.mobile
                FROM applications a JOIN students s ON s.id = a.student_id WHERE a.id = ?""", (aid,))
    if not rows:
        abort(404)
    r = rows[0]
    r["data"] = json.loads(r["data"])
    r["audit"] = q("SELECT actor, action, detail, created FROM audit_log WHERE target = ? ORDER BY id DESC",
                   (r["app_code"],))
    return jsonify(r)


@bp.post("/api/admin/admissions/<int:aid>/decision")
@admin_required
def decide(aid):
    d = body()
    action = d.get("action")
    note = str(d.get("note", "")).strip()[:500]
    if action not in RULES:
        return jsonify(error="Unknown action"), 400
    allowed, new_status, needs_note = RULES[action]
    if needs_note and not note:
        return jsonify(error="A reason or message is required for this action"), 400
    rows = q("SELECT app_code, status FROM applications WHERE id = ?", (aid,))
    if not rows:
        abort(404)
    if rows[0]["status"] not in allowed:
        return jsonify(error=f"Cannot {action.replace('_', ' ')} an application that is {rows[0]['status']}"), 409
    run("UPDATE applications SET status = ?, decision_note = ?, updated = CURRENT_TIMESTAMP WHERE id = ?",
        (new_status, note, aid))
    audit("admin", action, rows[0]["app_code"], note)
    return jsonify(ok=True, status=new_status)


@bp.put("/api/admin/admissions/<int:aid>/internal-note")
@admin_required
def internal_note(aid):
    rows = q("SELECT app_code FROM applications WHERE id = ?", (aid,))
    if not rows:
        abort(404)
    run("UPDATE applications SET internal_note = ? WHERE id = ?", (str(body().get("note", ""))[:1000], aid))
    audit("admin", "internal_note", rows[0]["app_code"])
    return jsonify(ok=True)


# ---------- Admin: students and audit ----------

@bp.get("/api/admin/students")
@admin_required
def admin_students():
    return jsonify(q("""SELECT s.id, s.student_code, s.full_name, s.email, s.mobile, s.account_status,
                               s.created, s.last_login, a.status AS admission_status, a.app_code
                        FROM students s LEFT JOIN applications a ON a.student_id = s.id
                        ORDER BY s.id DESC"""))


@bp.patch("/api/admin/students/<int:sid>")
@admin_required
def set_student_status(sid):
    status = body().get("account_status")
    if status not in ("active", "suspended"):
        return jsonify(error="Invalid status"), 400
    rows = q("SELECT student_code FROM students WHERE id = ?", (sid,))
    if not rows:
        abort(404)
    run("UPDATE students SET account_status = ? WHERE id = ?", (status, sid))
    audit("admin", "account_" + status, rows[0]["student_code"])
    return jsonify(ok=True)


@bp.get("/api/admin/audit")
@admin_required
def audit_list():
    return jsonify(q("SELECT actor, action, target, detail, created FROM audit_log ORDER BY id DESC LIMIT 200"))
