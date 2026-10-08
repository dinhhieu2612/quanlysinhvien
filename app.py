"""Hệ thống quản lý sinh viên - Flask + SQLite.  Chạy: python app.py  ->  http://127.0.0.1:5000"""
import os, secrets, sqlite3
from functools import wraps
from flask import Flask, g, request, session, redirect, url_for, flash, render_template, abort
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "doi-khoa-nay-khi-trien-khai")
DB = os.environ.get("SV_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sv.db"))
ROLES = {"student": "Sinh viên", "teacher": "Giảng viên", "admin": "Quản trị"}
DAYS = {2: "Thứ hai", 3: "Thứ ba", 4: "Thứ tư", 5: "Thứ năm", 6: "Thứ sáu", 7: "Thứ bảy"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student', full_name TEXT NOT NULL, email TEXT DEFAULT '',
  phone TEXT DEFAULT '', code TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, credits INTEGER NOT NULL,
  teacher_id INTEGER REFERENCES users(id), day INTEGER NOT NULL, start TEXT NOT NULL,
  end TEXT NOT NULL, room TEXT DEFAULT '', capacity INTEGER NOT NULL DEFAULT 40);
CREATE TABLE IF NOT EXISTS enrollments(
  id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE, score REAL,
  UNIQUE(student_id, course_id));
"""

# ---------- Cơ sở dữ liệu ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

def q(sql, *a):
    return db().execute(sql, a).fetchall()

def one(sql, *a):
    return db().execute(sql, a).fetchone()

def ex(sql, *a):
    cur = db().execute(sql, a)
    db().commit()
    return cur

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        users = [("admin", "admin123", "admin", "Quản trị viên", ""),
                 ("gv1", "gv123456", "teacher", "TS. Nguyễn Văn An", "GV001"),
                 ("gv2", "gv123456", "teacher", "ThS. Lê Thị Bình", "GV002"),
                 ("sv1", "sv123456", "student", "Trần Minh Châu", "SV1001"),
                 ("sv2", "sv123456", "student", "Phạm Quốc Dũng", "SV1002")]
        for u, p, r, n, code in users:
            c.execute("INSERT INTO users(username,password_hash,role,full_name,code,email) VALUES(?,?,?,?,?,?)",
                      (u, generate_password_hash(p), r, n, code, f"{u}@truong.edu.vn"))
        courses = [("INT101", "Nhập môn lập trình", 3, 2, 2, "07:30", "09:30", "A101", 40),
                   ("INT202", "Cơ sở dữ liệu", 3, 2, 3, "09:45", "11:45", "A203", 2),
                   ("MAT101", "Giải tích 1", 4, 3, 2, "07:30", "10:30", "B102", 50),
                   ("ENG101", "Tiếng Anh 1", 2, 2, 4, "13:00", "15:00", "C305", 40)]
        for code, name, cr, t, d, s, e, room, cap in courses:
            c.execute("INSERT INTO courses(code,name,credits,teacher_id,day,start,end,room,capacity) VALUES(?,?,?,?,?,?,?,?,?)",
                      (code, name, cr, t, d, s, e, room, cap))
        c.execute("INSERT INTO enrollments(student_id,course_id,score) VALUES(4,1,8.5)")
        c.commit()
    c.close()

# ---------- Đăng nhập, phân quyền, CSRF ----------
@app.before_request
def load_user():
    g.user = one("SELECT * FROM users WHERE id=?", session["uid"]) if "uid" in session else None
    session.setdefault("_t", secrets.token_hex(16))
    if request.method == "POST" and request.form.get("_t") != session["_t"]:
        abort(400, "Phiên làm việc không hợp lệ. Hãy tải lại trang.")

@app.context_processor
def inject():
    return dict(user=g.get("user"), token=session.get("_t"), ROLES=ROLES, DAYS=DAYS, letter=letter)

def need(*roles):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            if not g.user:
                flash("Hãy đăng nhập để tiếp tục.", "err")
                return redirect(url_for("login"))
            if roles and g.user["role"] not in roles:
                abort(403)
            return f(*a, **k)
        return wrap
    return deco

def letter(s):
    if s is None: return "–"
    return "A" if s >= 8.5 else "B" if s >= 7 else "C" if s >= 5.5 else "D" if s >= 4 else "F"

@app.errorhandler(403)
def e403(_): return render_template("error.html", title="Không có quyền", msg="Tài khoản của bạn không được phép mở trang này."), 403

@app.errorhandler(404)
def e404(_): return render_template("error.html", title="Không tìm thấy", msg="Trang bạn tìm không tồn tại."), 404

@app.errorhandler(400)
def e400(e): return render_template("error.html", title="Yêu cầu không hợp lệ", msg=e.description), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = one("SELECT * FROM users WHERE username=?", request.form.get("username", "").strip())
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear(); session["uid"] = u["id"]
            return redirect(url_for("home"))
        flash("Tên đăng nhập hoặc mật khẩu không đúng.", "err")
    return render_template("login.html", title="Đăng nhập")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = {k: request.form.get(k, "").strip() for k in ("username", "full_name", "email")}
        pw = request.form.get("password", "")
        if not all(f.values()) or len(pw) < 6:
            flash("Điền đủ các trường; mật khẩu tối thiểu 6 ký tự.", "err")
        elif one("SELECT 1 FROM users WHERE username=?", f["username"]):
            flash("Tên đăng nhập đã được dùng. Hãy chọn tên khác.", "err")
        else:
            cur = ex("INSERT INTO users(username,password_hash,role,full_name,email) VALUES(?,?,'student',?,?)",
                     f["username"], generate_password_hash(pw), f["full_name"], f["email"])
            ex("UPDATE users SET code=? WHERE id=?", f"SV{1000 + cur.lastrowid}", cur.lastrowid)
            flash("Đã tạo tài khoản. Bạn có thể đăng nhập.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html", title="Đăng ký tài khoản")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Trang chính, thông tin cá nhân ----------
@app.route("/")
@need()
def home():
    s = {}
    if g.user["role"] == "student":
        s["courses"] = one("SELECT COUNT(*) n, COALESCE(SUM(c.credits),0) cr FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.student_id=?", g.user["id"])
    elif g.user["role"] == "teacher":
        s["courses"] = one("SELECT COUNT(*) n FROM courses WHERE teacher_id=?", g.user["id"])
    else:
        s["users"] = one("SELECT COUNT(*) n FROM users")
        s["courses"] = one("SELECT COUNT(*) n FROM courses")
    return render_template("home.html", title="Trang chủ", s=s)

@app.route("/profile", methods=["GET", "POST"])
@need()
def profile():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        if not name:
            flash("Họ tên không được để trống.", "err")
            return redirect(url_for("profile"))
        ex("UPDATE users SET full_name=?, email=?, phone=? WHERE id=?", name,
           request.form.get("email", "").strip(), request.form.get("phone", "").strip(), g.user["id"])
        new = request.form.get("new_password", "")
        if new:
            if not check_password_hash(g.user["password_hash"], request.form.get("old_password", "")) or len(new) < 6:
                flash("Mật khẩu hiện tại sai hoặc mật khẩu mới ngắn hơn 6 ký tự. Thông tin khác đã được lưu.", "err")
                return redirect(url_for("profile"))
            ex("UPDATE users SET password_hash=? WHERE id=?", generate_password_hash(new), g.user["id"])
        flash("Đã lưu thông tin.", "ok")
        return redirect(url_for("profile"))
    return render_template("profile.html", title="Thông tin cá nhân")

# ---------- Học phần ----------
def overlaps(a, b):
    return a["day"] == b["day"] and a["start"] < b["end"] and b["start"] < a["end"]

@app.route("/courses")
@need()
def courses():
    rows = q("""SELECT c.*, u.full_name teacher,
        (SELECT COUNT(*) FROM enrollments WHERE course_id=c.id) taken,
        (SELECT id FROM enrollments WHERE course_id=c.id AND student_id=?) mine
        FROM courses c LEFT JOIN users u ON u.id=c.teacher_id ORDER BY c.code""", g.user["id"])
    return render_template("courses.html", title="Học phần", rows=rows)

@app.post("/courses/<int:cid>/register")
@need("student")
def enroll(cid):
    c = one("SELECT * FROM courses WHERE id=?", cid) or abort(404)
    if one("SELECT 1 FROM enrollments WHERE student_id=? AND course_id=?", g.user["id"], cid):
        flash("Bạn đã đăng ký học phần này.", "err")
    elif one("SELECT COUNT(*) n FROM enrollments WHERE course_id=?", cid)["n"] >= c["capacity"]:
        flash(f"{c['code']} đã đủ {c['capacity']} chỗ.", "err")
    else:
        mine = q("SELECT c.* FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.student_id=?", g.user["id"])
        clash = next((m for m in mine if overlaps(m, c)), None)
        if clash:
            flash(f"{c['code']} trùng giờ với {clash['code']} ({DAYS[c['day']]}, {clash['start']}–{clash['end']}).", "err")
        else:
            ex("INSERT INTO enrollments(student_id,course_id) VALUES(?,?)", g.user["id"], cid)
            flash(f"Đã đăng ký {c['code']} – {c['name']}.", "ok")
    return redirect(url_for("courses"))

@app.post("/courses/<int:cid>/cancel")
@need("student")
def cancel(cid):
    e = one("SELECT * FROM enrollments WHERE student_id=? AND course_id=?", g.user["id"], cid)
    if not e:
        flash("Bạn chưa đăng ký học phần này.", "err")
    elif e["score"] is not None:
        flash("Học phần đã có điểm nên không thể hủy.", "err")
    else:
        ex("DELETE FROM enrollments WHERE id=?", e["id"])
        flash("Đã hủy học phần.", "ok")
    return redirect(url_for("courses"))

# ---------- Điểm ----------
@app.route("/grades")
@need("student")
def grades():
    rows = q("SELECT c.code,c.name,c.credits,e.score FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.student_id=? ORDER BY c.code", g.user["id"])
    done = [r for r in rows if r["score"] is not None]
    cr = sum(r["credits"] for r in done)
    gpa = round(sum(r["score"] * r["credits"] for r in done) / cr, 2) if cr else None
    return render_template("grades.html", title="Xem điểm", rows=rows, gpa=gpa, cr=cr)

@app.route("/courses/<int:cid>/grades", methods=["GET", "POST"])
@need("teacher", "admin")
def grade_entry(cid):
    c = one("SELECT * FROM courses WHERE id=?", cid) or abort(404)
    if g.user["role"] == "teacher" and c["teacher_id"] != g.user["id"]:
        abort(403)
    if request.method == "POST":
        for k, v in request.form.items():
            if k.startswith("s_"):
                try:
                    val = float(v) if v.strip() else None
                    if val is not None and not 0 <= val <= 10: raise ValueError
                except ValueError:
                    flash("Điểm phải là số từ 0 đến 10.", "err")
                    return redirect(request.url)
                ex("UPDATE enrollments SET score=? WHERE id=? AND course_id=?", val, int(k[2:]), cid)
        flash("Đã lưu điểm.", "ok")
        return redirect(request.url)
    rows = q("SELECT e.id, e.score, u.full_name, u.code FROM enrollments e JOIN users u ON u.id=e.student_id WHERE e.course_id=? ORDER BY u.full_name", cid)
    return render_template("grade_entry.html", title=f"Nhập điểm {c['code']}", c=c, rows=rows)

# ---------- Thời khóa biểu ----------
@app.route("/timetable")
@need()
def timetable():
    r = g.user["role"]
    base = "SELECT c.*, u.full_name teacher FROM courses c LEFT JOIN users u ON u.id=c.teacher_id "
    if r == "student":
        rows = q(base + "JOIN enrollments e ON e.course_id=c.id WHERE e.student_id=? ORDER BY c.day,c.start", g.user["id"])
    elif r == "teacher":
        rows = q(base + "WHERE c.teacher_id=? ORDER BY c.day,c.start", g.user["id"])
    else:
        rows = q(base + "ORDER BY c.day,c.start")
    return render_template("timetable.html", title="Thời khóa biểu", rows=rows)

# ---------- Tìm kiếm sinh viên ----------
@app.route("/students")
@need("teacher", "admin")
def students():
    term = request.args.get("q", "").strip()
    like = f"%{term}%"
    rows = q("SELECT id,username,full_name,code,email FROM users WHERE role='student' AND (full_name LIKE ? OR code LIKE ? OR username LIKE ? OR email LIKE ?) ORDER BY full_name",
             like, like, like, like)
    return render_template("students.html", title="Tìm sinh viên", rows=rows, term=term)

# ---------- Quản trị ----------
@app.route("/admin")
@need("admin")
def admin():
    return render_template("admin.html", title="Quản trị",
                           users=q("SELECT * FROM users ORDER BY role,full_name"),
                           teachers=q("SELECT id,full_name FROM users WHERE role='teacher'"),
                           courses=q("SELECT c.*, u.full_name teacher FROM courses c LEFT JOIN users u ON u.id=c.teacher_id ORDER BY c.code"))

@app.post("/admin/users/<int:uid>/role")
@need("admin")
def set_role(uid):
    role = request.form.get("role")
    if role not in ROLES or uid == g.user["id"]:
        flash("Không thể đổi vai trò này (không được tự đổi vai trò của mình).", "err")
    else:
        ex("UPDATE users SET role=? WHERE id=?", role, uid)
        flash("Đã cập nhật vai trò.", "ok")
    return redirect(url_for("admin"))

@app.post("/admin/users/<int:uid>/delete")
@need("admin")
def del_user(uid):
    if uid == g.user["id"]:
        flash("Bạn không thể xóa chính mình.", "err")
    else:
        ex("DELETE FROM users WHERE id=?", uid)
        flash("Đã xóa tài khoản.", "ok")
    return redirect(url_for("admin"))

@app.post("/admin/courses")
@need("admin")
def add_course():
    f = request.form
    try:
        ex("INSERT INTO courses(code,name,credits,teacher_id,day,start,end,room,capacity) VALUES(?,?,?,?,?,?,?,?,?)",
           f["code"].strip().upper(), f["name"].strip(), int(f["credits"]), f.get("teacher_id") or None,
           int(f["day"]), f["start"], f["end"], f.get("room", "").strip(), int(f["capacity"]))
        flash("Đã thêm học phần.", "ok")
    except (sqlite3.IntegrityError, KeyError, ValueError):
        flash("Không thêm được: kiểm tra mã học phần (không trùng) và các số liệu.", "err")
    return redirect(url_for("admin"))

# ---------- Giao diện ----------
CSS = """
:root{--ink:#17263b;--mut:#5d6b7e;--bg:#f6f4ef;--card:#fff;--line:#d9dde3;--ac:#0b6e78;--acd:#08545c;--bad:#a63a26;--good:#1f7a4a}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;font:16px/1.55 'Be Vietnam Pro',system-ui,sans-serif;color:var(--ink);background:var(--bg)}
a{color:var(--ac)}h1{font-size:1.5rem;margin:0 0 1rem;line-height:1.25}h2{font-size:1.1rem;margin:1.6rem 0 .6rem}
header{background:var(--ink);color:#fff;padding:.6rem 1rem;display:flex;flex-wrap:wrap;gap:.25rem 1rem;align-items:center}
header a,header button.link{color:#e8eef5;text-decoration:none;padding:.5rem .1rem;min-height:44px;display:inline-flex;align-items:center;background:none;border:0;font:inherit;cursor:pointer}
header a:hover,header button.link:hover{text-decoration:underline}.brand{font-weight:700;margin-right:auto}
nav{display:flex;flex-wrap:wrap;gap:0 1rem}.who{font-size:.85rem;opacity:.8}
main{max-width:60rem;margin:0 auto;padding:1.25rem 1rem 3rem}
.box{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1rem}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line)}
th,td{text-align:left;padding:.6rem .7rem;border-bottom:1px solid var(--line);vertical-align:middle}th{font-size:.85rem;color:var(--mut);font-weight:600;background:#fafaf8}
label{display:block;font-weight:600;font-size:.9rem;margin:.8rem 0 .25rem}
input,select{font:inherit;width:100%;min-height:44px;padding:.5rem .65rem;border:1px solid #aab3be;border-radius:4px;background:#fff;color:var(--ink)}
td input,td select{min-width:5rem}
.btn{font:inherit;font-weight:600;min-height:44px;padding:.5rem 1rem;border:0;border-radius:4px;background:var(--ac);color:#fff;cursor:pointer}
.btn:hover{background:var(--acd)}.btn.sec{background:#fff;color:var(--ink);border:1px solid #aab3be}.btn.bad{background:var(--bad)}
.btn.sm{min-height:44px;padding:.3rem .8rem}
:focus-visible{outline:3px solid #e0a100;outline-offset:2px}
.msg{padding:.7rem 1rem;border-radius:4px;margin-bottom:1rem;border-left:5px solid}.msg.ok{background:#e4f3ea;border-color:var(--good)}.msg.err{background:#fbe9e5;border-color:var(--bad)}
.narrow{max-width:26rem;margin:2rem auto}.stats{display:flex;flex-wrap:wrap;gap:1rem}.stat{flex:1 1 9rem}.stat b{font-size:1.9rem;display:block;line-height:1.1}
.mut{color:var(--mut)}.tag{font-size:.8rem;border:1px solid var(--line);border-radius:3px;padding:.05rem .4rem;background:#fff}
form.inline{display:inline}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:0 .8rem}
.slot{display:flex;gap:1rem;padding:.7rem 0;border-bottom:1px solid var(--line)}.slot time{min-width:6.5rem;font-weight:600}
@media(prefers-reduced-motion:no-preference){.btn{transition:background .15s}}
"""

BASE = """<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} – Cổng sinh viên</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;600;700&display=swap" rel="stylesheet">
<style>""" + CSS + """</style></head><body>
<header><a class="brand" href="{{ url_for('home') }}">Cổng sinh viên</a>
{% if user %}<nav>
<a href="{{ url_for('courses') }}">Học phần</a><a href="{{ url_for('timetable') }}">Thời khóa biểu</a>
{% if user.role=='student' %}<a href="{{ url_for('grades') }}">Điểm</a>{% endif %}
{% if user.role in ('teacher','admin') %}<a href="{{ url_for('students') }}">Tìm sinh viên</a>{% endif %}
{% if user.role=='admin' %}<a href="{{ url_for('admin') }}">Quản trị</a>{% endif %}
<a href="{{ url_for('profile') }}">Cá nhân</a></nav>
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="_t" value="{{ token }}"><button class="link">Đăng xuất ({{ user.username }})</button></form>
{% endif %}</header><main>
{% for c, m in get_flashed_messages(with_categories=true) %}<div class="msg {{ c }}" role="status">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

CSRF = '<input type="hidden" name="_t" value="{{ token }}">'

T = {"base.html": BASE,
"error.html": """{% extends 'base.html' %}{% block body %}<h1>{{ title }}</h1><p>{{ msg }}</p><p><a href="{{ url_for('home') }}">Về trang chủ</a></p>{% endblock %}""",
"login.html": """{% extends 'base.html' %}{% block body %}<div class="box narrow"><h1>Đăng nhập</h1>
<form method="post">""" + CSRF + """<label for="u">Tên đăng nhập</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Mật khẩu</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<p><button class="btn">Đăng nhập</button></p></form><p class="mut">Chưa có tài khoản? <a href="{{ url_for('register') }}">Đăng ký sinh viên</a></p>
<p class="mut" style="font-size:.85rem">Tài khoản mẫu: admin/admin123 · gv1/gv123456 · sv1/sv123456</p></div>{% endblock %}""",
"register.html": """{% extends 'base.html' %}{% block body %}<div class="box narrow"><h1>Đăng ký tài khoản</h1>
<form method="post">""" + CSRF + """<label for="n">Họ và tên</label><input id="n" name="full_name" required>
<label for="e">Email</label><input id="e" name="email" type="email" required>
<label for="u">Tên đăng nhập</label><input id="u" name="username" autocomplete="username" required>
<label for="p">Mật khẩu (tối thiểu 6 ký tự)</label><input id="p" name="password" type="password" minlength="6" autocomplete="new-password" required>
<p><button class="btn">Tạo tài khoản</button></p></form><p class="mut">Đã có tài khoản? <a href="{{ url_for('login') }}">Đăng nhập</a></p></div>{% endblock %}""",
"home.html": """{% extends 'base.html' %}{% block body %}<h1>Xin chào, {{ user.full_name }}</h1>
<p class="mut">{{ ROLES[user.role] }}{% if user.code %} · Mã {{ user.code }}{% endif %}</p>
<div class="stats">
{% if user.role=='student' %}<div class="box stat"><b>{{ s.courses.n }}</b>học phần đã đăng ký</div><div class="box stat"><b>{{ s.courses.cr }}</b>tín chỉ</div>
{% elif user.role=='teacher' %}<div class="box stat"><b>{{ s.courses.n }}</b>học phần đang dạy</div>
{% else %}<div class="box stat"><b>{{ s.users.n }}</b>tài khoản</div><div class="box stat"><b>{{ s.courses.n }}</b>học phần</div>{% endif %}</div>
<h2>Việc thường làm</h2><p>
{% if user.role=='student' %}<a class="btn" href="{{ url_for('courses') }}">Đăng ký học phần</a> <a class="btn sec" href="{{ url_for('grades') }}">Xem điểm</a>
{% else %}<a class="btn" href="{{ url_for('students') }}">Tìm sinh viên</a> <a class="btn sec" href="{{ url_for('courses') }}">Danh sách học phần</a>{% endif %}</p>{% endblock %}""",
"profile.html": """{% extends 'base.html' %}{% block body %}<h1>Thông tin cá nhân</h1><div class="box"><form method="post">""" + CSRF + """
<p class="mut">Tên đăng nhập: {{ user.username }} · Vai trò: {{ ROLES[user.role] }}{% if user.code %} · Mã: {{ user.code }}{% endif %}</p>
<div class="row"><div><label for="n">Họ và tên</label><input id="n" name="full_name" value="{{ user.full_name }}" required></div>
<div><label for="e">Email</label><input id="e" name="email" type="email" value="{{ user.email }}"></div>
<div><label for="ph">Số điện thoại</label><input id="ph" name="phone" value="{{ user.phone }}"></div></div>
<h2>Đổi mật khẩu (không bắt buộc)</h2><div class="row"><div><label for="o">Mật khẩu hiện tại</label><input id="o" name="old_password" type="password" autocomplete="current-password"></div>
<div><label for="np">Mật khẩu mới</label><input id="np" name="new_password" type="password" minlength="6" autocomplete="new-password"></div></div>
<p><button class="btn">Lưu thay đổi</button></p></form></div>{% endblock %}""",
"courses.html": """{% extends 'base.html' %}{% block body %}<h1>Học phần</h1><div class="wrap"><table>
<tr><th>Mã</th><th>Tên học phần</th><th>TC</th><th>Giảng viên</th><th>Lịch</th><th>Chỗ</th><th></th></tr>
{% for c in rows %}<tr><td>{{ c.code }}</td><td>{{ c.name }}</td><td>{{ c.credits }}</td><td>{{ c.teacher or '–' }}</td>
<td>{{ DAYS[c.day] }}, {{ c.start }}–{{ c.end }}<br><span class="mut">{{ c.room }}</span></td><td>{{ c.taken }}/{{ c.capacity }}</td><td>
{% if user.role=='student' %}{% if c.mine %}<form class="inline" method="post" action="{{ url_for('cancel', cid=c.id) }}">""" + CSRF + """<button class="btn bad sm">Hủy</button></form>
{% else %}<form class="inline" method="post" action="{{ url_for('enroll', cid=c.id) }}">""" + CSRF + """<button class="btn sm">Đăng ký</button></form>{% endif %}
{% elif user.role=='admin' or c.teacher==user.full_name %}<a class="btn sec sm" href="{{ url_for('grade_entry', cid=c.id) }}">Nhập điểm</a>{% endif %}</td></tr>{% endfor %}</table></div>{% endblock %}""",
"grades.html": """{% extends 'base.html' %}{% block body %}<h1>Điểm của tôi</h1>
<p>Điểm trung bình tích lũy: <b>{{ gpa if gpa is not none else 'chưa có' }}</b> <span class="mut">({{ cr }} tín chỉ đã có điểm, thang 10)</span></p>
{% if rows %}<div class="wrap"><table><tr><th>Mã</th><th>Học phần</th><th>TC</th><th>Điểm</th><th>Xếp loại</th></tr>
{% for r in rows %}<tr><td>{{ r.code }}</td><td>{{ r.name }}</td><td>{{ r.credits }}</td><td>{{ r.score if r.score is not none else 'Chưa có' }}</td><td>{{ letter(r.score) }}</td></tr>{% endfor %}</table></div>
{% else %}<p>Bạn chưa đăng ký học phần nào. <a href="{{ url_for('courses') }}">Đăng ký ngay</a></p>{% endif %}{% endblock %}""",
"grade_entry.html": """{% extends 'base.html' %}{% block body %}<h1>Nhập điểm {{ c.code }} – {{ c.name }}</h1>
{% if rows %}<form method="post">""" + CSRF + """<div class="wrap"><table><tr><th>Mã SV</th><th>Họ tên</th><th>Điểm (0–10)</th></tr>
{% for r in rows %}<tr><td>{{ r.code }}</td><td>{{ r.full_name }}</td><td><input name="s_{{ r.id }}" type="number" min="0" max="10" step="0.1" value="{{ r.score if r.score is not none else '' }}" aria-label="Điểm {{ r.full_name }}"></td></tr>{% endfor %}</table></div>
<p><button class="btn">Lưu điểm</button></p></form>{% else %}<p>Chưa có sinh viên đăng ký học phần này.</p>{% endif %}{% endblock %}""",
"timetable.html": """{% extends 'base.html' %}{% block body %}<h1>Thời khóa biểu</h1>
{% for d, name in DAYS.items() %}{% set day = rows|selectattr('day','equalto',d)|list %}{% if day %}<h2>{{ name }}</h2><div class="box">
{% for c in day %}<div class="slot"><time>{{ c.start }}–{{ c.end }}</time><div><b>{{ c.code }} · {{ c.name }}</b><br><span class="mut">Phòng {{ c.room }} · {{ c.teacher or 'Chưa phân công' }}</span></div></div>{% endfor %}</div>{% endif %}{% endfor %}
{% if not rows %}<p>Chưa có lịch học. {% if user.role=='student' %}<a href="{{ url_for('courses') }}">Đăng ký học phần</a>{% endif %}</p>{% endif %}{% endblock %}""",
"students.html": """{% extends 'base.html' %}{% block body %}<h1>Tìm sinh viên</h1>
<form method="get" role="search"><label for="q">Họ tên, mã sinh viên, tên đăng nhập hoặc email</label><div style="display:flex;gap:.5rem"><input id="q" name="q" value="{{ term }}"><button class="btn">Tìm</button></div></form><br>
{% if rows %}<div class="wrap"><table><tr><th>Mã SV</th><th>Họ tên</th><th>Tên đăng nhập</th><th>Email</th></tr>
{% for r in rows %}<tr><td>{{ r.code }}</td><td>{{ r.full_name }}</td><td>{{ r.username }}</td><td>{{ r.email }}</td></tr>{% endfor %}</table></div>
{% else %}<p>Không có sinh viên khớp “{{ term }}”. Thử một phần của họ tên hoặc mã.</p>{% endif %}{% endblock %}""",
"admin.html": """{% extends 'base.html' %}{% block body %}<h1>Quản trị</h1><h2>Tài khoản</h2><div class="wrap"><table>
<tr><th>Tên đăng nhập</th><th>Họ tên</th><th>Vai trò</th><th></th></tr>
{% for u in users %}<tr><td>{{ u.username }}</td><td>{{ u.full_name }}</td><td>
<form class="inline" method="post" action="{{ url_for('set_role', uid=u.id) }}">""" + CSRF + """<select name="role" aria-label="Vai trò của {{ u.username }}" style="width:auto">
{% for k, v in ROLES.items() %}<option value="{{ k }}" {{ 'selected' if u.role==k }}>{{ v }}</option>{% endfor %}</select> <button class="btn sec sm">Lưu</button></form></td><td>
{% if u.id!=user.id %}<form class="inline" method="post" action="{{ url_for('del_user', uid=u.id) }}" onsubmit="return confirm('Xóa tài khoản {{ u.username }}?')">""" + CSRF + """<button class="btn bad sm">Xóa</button></form>{% endif %}</td></tr>{% endfor %}</table></div>
<h2>Thêm học phần</h2><div class="box"><form method="post" action="{{ url_for('add_course') }}">""" + CSRF + """<div class="row">
<div><label for="c1">Mã</label><input id="c1" name="code" required></div><div><label for="c2">Tên</label><input id="c2" name="name" required></div>
<div><label for="c3">Tín chỉ</label><input id="c3" name="credits" type="number" min="1" max="10" value="3" required></div>
<div><label for="c4">Giảng viên</label><select id="c4" name="teacher_id"><option value="">Chưa phân công</option>{% for t in teachers %}<option value="{{ t.id }}">{{ t.full_name }}</option>{% endfor %}</select></div>
<div><label for="c5">Thứ</label><select id="c5" name="day">{% for d, n in DAYS.items() %}<option value="{{ d }}">{{ n }}</option>{% endfor %}</select></div>
<div><label for="c6">Bắt đầu</label><input id="c6" name="start" type="time" value="07:30" required></div><div><label for="c7">Kết thúc</label><input id="c7" name="end" type="time" value="09:30" required></div>
<div><label for="c8">Phòng</label><input id="c8" name="room"></div><div><label for="c9">Sĩ số tối đa</label><input id="c9" name="capacity" type="number" min="1" value="40" required></div></div>
<p><button class="btn">Thêm học phần</button></p></form></div>
<h2>Học phần hiện có ({{ courses|length }})</h2><div class="wrap"><table><tr><th>Mã</th><th>Tên</th><th>Giảng viên</th></tr>
{% for c in courses %}<tr><td>{{ c.code }}</td><td>{{ c.name }}</td><td>{{ c.teacher or '–' }}</td></tr>{% endfor %}</table></div>{% endblock %}""",
}
app.jinja_loader = DictLoader(T)

init_db()
if __name__ == "__main__":
    app.run(debug=os.environ.get("DEBUG") == "1")
