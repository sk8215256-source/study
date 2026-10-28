import os
import sqlite3
import uuid
from functools import wraps

from flask import Flask, abort, g, jsonify, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE, "uploads")
DB_PATH = os.path.join(BASE, "studypoint.db")
ALLOWED_EXT = {"pdf", "doc", "docx", "ppt", "pptx", "jpg", "jpeg", "png", "zip"}

# Change these before hosting, or set them as environment variables
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@studypoint.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "StudyPoint@2026")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key")

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS") == "1"  # set HTTPS=1 on a live HTTPS host
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB per upload
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=()):
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def remove_file(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if os.path.isfile(path):
        os.remove(path)


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, email TEXT, pw_hash TEXT);
        CREATE TABLE IF NOT EXISTS classes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY, class_id INTEGER, title TEXT, subject TEXT,
            filename TEXT, original TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY, class_id INTEGER, name TEXT, phone TEXT, email TEXT,
            message TEXT, status TEXT DEFAULT 'new', created TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    # The admin account always follows ADMIN_EMAIL and ADMIN_PASSWORD from settings
    con.execute("DELETE FROM admins")
    con.execute("INSERT INTO admins (email, pw_hash) VALUES (?, ?)",
                (ADMIN_EMAIL.lower(), generate_password_hash(ADMIN_PASSWORD)))
    if con.execute("SELECT COUNT(*) FROM classes").fetchone()[0] == 0:
        con.executemany("INSERT INTO classes (name, description) VALUES (?, ?)", [
            ("Class 6", "Strong foundation in Math, English, Science and Bangla"),
            ("Class 7", "Concept-based learning with weekly tests"),
            ("Class 8", "Preparation for JSC with regular practice exams"),
            ("Class 9", "SSC foundation: full syllabus and model tests"),
            ("Class 10", "SSC board-exam focus with previous-year questions"),
            ("Class 11", "HSC first year: Science, Commerce and Arts"),
        ])
    con.commit()
    con.close()


init_db()


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify(error="Please log in as admin"), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------- Public pages ----------

@app.get("/")
def home():
    return render_template("index.html")


@app.get("/admin")
def admin_page():
    return render_template("admin.html")


# ---------- Public API ----------

@app.get("/api/classes")
def list_classes():
    return jsonify(query("""
        SELECT c.id, c.name, c.description,
               (SELECT COUNT(*) FROM materials m WHERE m.class_id = c.id) AS materials
        FROM classes c ORDER BY c.id
    """))


@app.get("/api/materials")
def list_materials():
    class_id = request.args.get("class_id", type=int)
    sql = """SELECT m.id, m.class_id, m.title, m.subject, m.original, m.created, c.name AS class_name
             FROM materials m LEFT JOIN classes c ON c.id = m.class_id"""
    args = ()
    if class_id:
        sql += " WHERE m.class_id = ?"
        args = (class_id,)
    return jsonify(query(sql + " ORDER BY m.id DESC", args))


@app.get("/download/<int:material_id>")
def download(material_id):
    rows = query("SELECT filename, original FROM materials WHERE id = ?", (material_id,))
    if not rows:
        abort(404)
    return send_from_directory(UPLOAD_DIR, rows[0]["filename"], as_attachment=True,
                               download_name=rows[0]["original"])


@app.post("/api/bookings")
def create_booking():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:100]
    phone = str(d.get("phone", "")).strip()[:30]
    if not name or not phone:
        return jsonify(error="Name and phone number are required"), 400
    try:
        class_id = int(d.get("class_id"))
    except (TypeError, ValueError):
        class_id = None
    db = get_db()
    db.execute(
        "INSERT INTO bookings (class_id, name, phone, email, message) VALUES (?, ?, ?, ?, ?)",
        (class_id, name, phone, str(d.get("email", ""))[:120], str(d.get("message", ""))[:500]))
    db.commit()
    return jsonify(ok=True, message="Booking received! We will contact you soon."), 201


# ---------- Admin auth ----------

@app.post("/api/admin/login")
def admin_login():
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    password = str(d.get("password", ""))
    rows = query("SELECT pw_hash FROM admins WHERE email = ?", (email,))
    if rows and check_password_hash(rows[0]["pw_hash"], password):
        session["admin"] = True
        return jsonify(ok=True)
    return jsonify(error="Wrong email or password"), 401


@app.post("/api/admin/logout")
def admin_logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/admin/me")
def admin_me():
    return jsonify(admin=bool(session.get("admin")))


# ---------- Admin: classes ----------

@app.post("/api/admin/classes")
@admin_required
def add_class():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:60]
    if not name:
        return jsonify(error="Class name is required"), 400
    db = get_db()
    cur = db.execute("INSERT INTO classes (name, description) VALUES (?, ?)",
                     (name, str(d.get("description", ""))[:300]))
    db.commit()
    return jsonify(id=cur.lastrowid), 201


@app.delete("/api/admin/classes/<int:class_id>")
@admin_required
def delete_class(class_id):
    db = get_db()
    for m in query("SELECT filename FROM materials WHERE class_id = ?", (class_id,)):
        remove_file(m["filename"])
    db.execute("DELETE FROM materials WHERE class_id = ?", (class_id,))
    db.execute("UPDATE bookings SET class_id = NULL WHERE class_id = ?", (class_id,))
    db.execute("DELETE FROM classes WHERE id = ?", (class_id,))
    db.commit()
    return jsonify(ok=True)


# ---------- Admin: notes / files ----------

@app.post("/api/admin/materials")
@admin_required
def upload_material():
    f = request.files.get("file")
    if not f or "." not in (f.filename or ""):
        return jsonify(error="Please choose a file"), 400
    ext = f.filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify(error="This file type is not allowed"), 400
    original = secure_filename(f.filename) or f"file.{ext}"
    stored = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(UPLOAD_DIR, stored))
    title = request.form.get("title", "").strip()[:120] or original
    subject = request.form.get("subject", "General").strip()[:40] or "General"
    db = get_db()
    cur = db.execute(
        "INSERT INTO materials (class_id, title, subject, filename, original) VALUES (?, ?, ?, ?, ?)",
        (request.form.get("class_id", type=int), title, subject, stored, original))
    db.commit()
    return jsonify(id=cur.lastrowid), 201


@app.delete("/api/admin/materials/<int:material_id>")
@admin_required
def delete_material(material_id):
    for m in query("SELECT filename FROM materials WHERE id = ?", (material_id,)):
        remove_file(m["filename"])
    db = get_db()
    db.execute("DELETE FROM materials WHERE id = ?", (material_id,))
    db.commit()
    return jsonify(ok=True)


# ---------- Admin: bookings ----------

@app.get("/api/admin/bookings")
@admin_required
def list_bookings():
    return jsonify(query("""
        SELECT b.id, b.name, b.phone, b.email, b.message, b.status, b.created, c.name AS class_name
        FROM bookings b LEFT JOIN classes c ON c.id = b.class_id
        ORDER BY b.id DESC
    """))


@app.patch("/api/admin/bookings/<int:booking_id>")
@admin_required
def update_booking(booking_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("new", "confirmed", "done", "cancelled"):
        return jsonify(error="Invalid status"), 400
    db = get_db()
    db.execute("UPDATE bookings SET status = ? WHERE id = ?", (status, booking_id))
    db.commit()
    return jsonify(ok=True)


@app.delete("/api/admin/bookings/<int:booking_id>")
@admin_required
def delete_booking(booking_id):
    db = get_db()
    db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    return jsonify(ok=True)


from admission import bp as admission_bp, init_admission_db  # noqa: E402

init_admission_db(DB_PATH)
app.register_blueprint(admission_bp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
