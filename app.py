"""
SQL Injection Demo – Unified Application
=========================================
A single Flask application that hosts both the VULNERABLE and SECURE
versions of every endpoint, plus an attack dashboard, a side-by-side
query comparison page, and an admin user-management panel.
"""

import os
import re
import sqlite3

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

# Try to import flask-limiter (optional – only used on secure routes)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(key_func=get_remote_address, app=app)
except ImportError:
    limiter = None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_db():
    return sqlite3.connect(DB_PATH)


def ensure_db():
    """Create tables and seed data if the DB is empty."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            email     TEXT NOT NULL UNIQUE,
            role      TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
        );

        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            price       REAL NOT NULL CHECK (price >= 0),
            category    TEXT NOT NULL,
            secret_code TEXT NOT NULL
        );
        """
    )
    # Seed only when tables are empty
    if cur.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, email, role, is_active) VALUES (?, ?, ?, ?, ?)",
            [
                ("admin", "Adm1n@2026!", "admin@example.com", "admin", 1),
                ("alice", "Alice#Pass91", "alice@example.com", "user", 1),
                ("bob", "Bob$Secure42", "bob@example.com", "user", 1),
                ("charlie", "Ch@rlie7788", "charlie@example.com", "user", 1),
            ],
        )
    if cur.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products (name, price, category, secret_code) VALUES (?, ?, ?, ?)",
            [
                ("Zero-Day Hoodie", 59.99, "Apparel", "INTERNAL-001"),
                ("Packet Sniffer Mug", 14.50, "Accessories", "INTERNAL-002"),
                ("Red Team Notebook", 9.99, "Stationery", "INTERNAL-003"),
                ("Firewall Sticker Pack", 6.25, "Accessories", "INTERNAL-004"),
                ("SOC Analyst Keyboard", 79.00, "Electronics", "INTERNAL-005"),
                ("Threat Intel Poster", 22.75, "Decor", "INTERNAL-006"),
            ],
        )
    conn.commit()
    conn.close()


# Run on import so the DB is always ready
ensure_db()


# ---------------------------------------------------------------------------
# Validation helpers (used by secure routes)
# ---------------------------------------------------------------------------

MIN_INPUT_LENGTH = 1
MAX_INPUT_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")
SQL_SPECIAL_PATTERN = re.compile(r"('|--|;)")
SQL_KEYWORD_PATTERN = re.compile(r"\b(UNION|DROP)\b", re.IGNORECASE)
SQL_BOOLEAN_CONDITION_PATTERN = re.compile(
    r"\b(OR|AND)\b\s+[A-Za-z0-9_()]+\s*(=|>|<|LIKE|IN)\s+[A-Za-z0-9_'\"()%]+",
    re.IGNORECASE,
)


def validate_input(value: str) -> tuple:
    if not isinstance(value, str):
        return False, "Input must be a string."
    if not (MIN_INPUT_LENGTH <= len(value) <= MAX_INPUT_LENGTH):
        return False, f"Input length must be {MIN_INPUT_LENGTH}–{MAX_INPUT_LENGTH} characters."
    if not USERNAME_PATTERN.fullmatch(value):
        return False, "Only letters, numbers, and underscores are allowed."
    if SQL_SPECIAL_PATTERN.search(value):
        return False, "SQL special characters are not allowed."
    if SQL_KEYWORD_PATTERN.search(value):
        return False, "SQL keywords are not allowed."
    if SQL_BOOLEAN_CONDITION_PATTERN.search(value):
        return False, "SQL boolean-style conditions are not allowed."
    return True, ""


def has_injection_markers(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in ("'", "--", ";", " union ", " or ", " and "))


# ---------------------------------------------------------------------------
# Attack definitions (used by dashboard + compare)
# ---------------------------------------------------------------------------

ATTACKS = [
    {
        "id": 1,
        "name": "Login Bypass",
        "description": "Classic OR-based payload that makes the WHERE clause always true, bypassing the password check entirely.",
        "action": "login_post",
        "payload": "' OR '1'='1' -- ",
        "password": "anything",
    },
    {
        "id": 2,
        "name": "Specific User Impersonation",
        "description": "Targets a known username and comments out the password condition with --.",
        "action": "login_post",
        "payload": "admin' -- ",
        "password": "wrong-password",
    },
    {
        "id": 3,
        "name": "UNION Data Extraction",
        "description": "Appends a UNION SELECT to the product search, leaking the users table into search results.",
        "action": "search_get",
        "payload": "%' UNION SELECT id, username, email, role FROM users -- ",
    },
    {
        "id": 4,
        "name": "Boolean Blind Injection",
        "description": "Injects OR 1=1 into the profile id parameter so every user row is returned.",
        "action": "profile_get",
        "payload": "1 OR 1=1",
    },
    {
        "id": 5,
        "name": "Error-Based Injection",
        "description": "Sends a single quote to break the SQL syntax and trigger a raw error / traceback.",
        "action": "login_post",
        "payload": "'",
        "password": "anything",
    },
    {
        "id": 6,
        "name": "Stacked Query (DROP TABLE)",
        "description": "Attempts to chain a DROP TABLE statement. SQLite blocks this, but MySQL / Postgres would not.",
        "action": "login_post",
        "payload": "'; DROP TABLE users; --",
        "password": "anything",
    },
]


# ---------------------------------------------------------------------------
# Compare-page query builder
# ---------------------------------------------------------------------------


def build_compare_cases():
    login_tpl = (
        "SELECT id, username, role, is_active FROM users "
        "WHERE username = '{username}' AND password = '{password}'"
    )
    login_param = (
        "SELECT id, username, role, is_active FROM users "
        "WHERE username = ? AND password = ?"
    )
    profile_tpl = (
        "SELECT id, username, email, role, is_active FROM users "
        "WHERE id = {user_id}"
    )
    profile_param = (
        "SELECT id, username, email, role, is_active FROM users "
        "WHERE id = ?"
    )
    search_tpl = (
        "SELECT id, name, price, category FROM products "
        "WHERE name LIKE '%{term}%' OR category LIKE '%{term}%'"
    )
    search_param = (
        "SELECT id, name, price, category FROM products "
        "WHERE name LIKE ? OR category LIKE ?"
    )

    a1 = ("' OR '1'='1' -- ", "anything")
    a2 = ("admin' -- ", "wrong-password")
    a3_payload = "%' UNION SELECT id, username, email, role FROM users -- "
    a4_payload = "1 OR 1=1"
    a5 = ("'", "anything")
    a6 = ("'; DROP TABLE users; --", "anything")

    return [
        {
            "name": "Attack #1 – Login Bypass",
            "payload": a1[0],
            "original_template": login_tpl,
            "injected_query": login_tpl.format(username=a1[0], password=a1[1]),
            "parameterized_query": login_param,
            "safe_params": a1,
        },
        {
            "name": "Attack #2 – User Impersonation",
            "payload": a2[0],
            "original_template": login_tpl,
            "injected_query": login_tpl.format(username=a2[0], password=a2[1]),
            "parameterized_query": login_param,
            "safe_params": a2,
        },
        {
            "name": "Attack #3 – UNION Extraction",
            "payload": a3_payload,
            "original_template": search_tpl,
            "injected_query": search_tpl.format(term=a3_payload),
            "parameterized_query": search_param,
            "safe_params": (f"%{a3_payload}%", f"%{a3_payload}%"),
        },
        {
            "name": "Attack #4 – Boolean Blind",
            "payload": a4_payload,
            "original_template": profile_tpl,
            "injected_query": profile_tpl.format(user_id=a4_payload),
            "parameterized_query": profile_param,
            "safe_params": (a4_payload,),
        },
        {
            "name": "Attack #5 – Error-Based",
            "payload": a5[0],
            "original_template": login_tpl,
            "injected_query": login_tpl.format(username=a5[0], password=a5[1]),
            "parameterized_query": login_param,
            "safe_params": a5,
        },
        {
            "name": "Attack #6 – Stacked Query",
            "payload": a6[0],
            "original_template": login_tpl,
            "injected_query": login_tpl.format(username=a6[0], password=a6[1]),
            "parameterized_query": login_param,
            "safe_params": a6,
        },
    ]


# ===================================================================
#  ROUTES
# ===================================================================

# ----- Landing page ------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


# ===================================================================
#  VULNERABLE routes (string concatenation – intentionally unsafe)
# ===================================================================


@app.route("/vulnerable/login", methods=["GET", "POST"])
def vuln_login():
    result = None
    explanation = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        query = (
            f"SELECT id, username, role, is_active FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        print(f"[VULNERABLE QUERY] {query}")

        conn = get_db()
        try:
            result = conn.cursor().execute(query).fetchone()
        except Exception as exc:
            explanation = f"SQL Error: {exc}"
            return render_template(
                "vulnerable/login.html",
                result=None,
                explanation_text=explanation,
                query_text=username,
                executed_query=query,
            )
        finally:
            conn.close()

        if has_injection_markers(username):
            explanation = (
                "The input altered the SQL logic so the WHERE clause matched rows "
                "without needing the real password."
                if result
                else "The payload attempted to break the SQL syntax. Check the query below."
            )
        elif not result:
            explanation = "Normal failed login – no injection detected."
        else:
            explanation = "Normal credential match – returned one user row."

    return render_template(
        "vulnerable/login.html",
        result=result,
        explanation_text=explanation,
        query_text=username,
    )


@app.route("/vulnerable/search")
def vuln_search():
    term = request.args.get("q", "")
    query = (
        f"SELECT id, name, price, category FROM products "
        f"WHERE name LIKE '%{term}%' OR category LIKE '%{term}%'"
    )
    print(f"[VULNERABLE QUERY] {query}")

    conn = get_db()
    try:
        rows = conn.cursor().execute(query).fetchall()
    except Exception as exc:
        return render_template(
            "vulnerable/search.html",
            query_text=term,
            results=[],
            explanation_text=f"SQL Error: {exc}",
        )
    finally:
        conn.close()

    tagged = []
    for r in rows:
        tagged.append(
            {"id": r[0], "name": r[1], "price": r[2], "category": r[3], "is_injected": False}
        )

    explanation = None
    tl = term.lower()
    if term:
        if " union " in tl:
            explanation = (
                "A UNION SELECT was injected – rows from the users table were appended "
                "to the product results. Highlighted rows below should NOT be visible."
            )
            for row in tagged:
                if not isinstance(row["price"], (int, float)):
                    row["is_injected"] = True
        elif " or " in tl and "=" in tl:
            explanation = "An always-true condition was injected, returning extra rows."
        else:
            explanation = "Normal search – no injection detected."

    return render_template(
        "vulnerable/search.html",
        query_text=term,
        results=tagged,
        explanation_text=explanation,
    )


@app.route("/vulnerable/profile")
def vuln_profile():
    user_id = request.args.get("id", "")
    if not user_id:
        return render_template(
            "vulnerable/profile.html",
            users=[],
            query_text="",
            explanation_text=None,
            suspicious_row_indexes=[],
        )

    query = (
        f"SELECT id, username, email, role, is_active FROM users "
        f"WHERE id = {user_id}"
    )
    print(f"[VULNERABLE QUERY] {query}")

    conn = get_db()
    try:
        rows = conn.cursor().execute(query).fetchall()
    except Exception as exc:
        return render_template(
            "vulnerable/profile.html",
            users=[],
            query_text=user_id,
            explanation_text=f"SQL Error: {exc}",
            suspicious_row_indexes=[],
        )
    finally:
        conn.close()

    explanation = None
    suspicious = []
    uid_lower = user_id.lower()

    if " or " in uid_lower and "=" in uid_lower:
        explanation = (
            "OR 1=1 made the WHERE clause always true – every user row is returned."
        )
        suspicious = list(range(len(rows)))
    elif " union " in uid_lower:
        explanation = "A UNION payload appended extra rows from another table."
        suspicious = list(range(len(rows)))
    else:
        explanation = "Normal profile lookup."

    return render_template(
        "vulnerable/profile.html",
        users=rows,
        query_text=user_id,
        explanation_text=explanation,
        suspicious_row_indexes=suspicious,
    )


@app.route("/vulnerable/dashboard")
def vuln_dashboard():
    if "username" not in session:
        return redirect(url_for("vuln_login"))
    return render_template(
        "vulnerable/dashboard.html",
        username=session.get("username"),
        role=session.get("role"),
        email=session.get("email"),
    )


# ===================================================================
#  SECURE routes (parameterized queries + input validation)
# ===================================================================


@app.route("/secure/login", methods=["GET", "POST"])
def sec_login():
    result = None
    validation_error = None
    auth_error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        is_valid, reason = validate_input(username)

        if not is_valid:
            app.logger.warning("Blocked suspicious input: %s", reason)
            validation_error = f"Suspicious input detected and blocked. Reason: {reason}"
            return render_template(
                "secure/login.html",
                result=None,
                validation_error=validation_error,
                auth_error=None,
            ), 400

        query = (
            "SELECT id, username, role, is_active FROM users "
            "WHERE username = ? AND password = ?"
        )
        params = (username, password)
        print(f"[SECURE QUERY] {query} | params={params!r}")

        conn = get_db()
        try:
            result = conn.cursor().execute(query, params).fetchone()
        except Exception:
            app.logger.exception("DB error in secure login")
            return "Something went wrong", 500
        finally:
            conn.close()

        if result is None:
            auth_error = "Invalid username or password."

    return render_template(
        "secure/login.html",
        result=result,
        validation_error=validation_error,
        auth_error=auth_error,
    )


@app.route("/secure/search")
def sec_search():
    term = request.args.get("q", "")
    query = (
        "SELECT id, name, price, category FROM products "
        "WHERE name LIKE ? OR category LIKE ?"
    )
    params = (f"%{term}%", f"%{term}%")
    print(f"[SECURE QUERY] {query} | params={params!r}")

    conn = get_db()
    try:
        rows = conn.cursor().execute(query, params).fetchall()
    except Exception:
        app.logger.exception("DB error in secure search")
        return "Something went wrong", 500
    finally:
        conn.close()

    return render_template("secure/search.html", query_text=term, results=rows)


@app.route("/secure/profile")
def sec_profile():
    user_id = request.args.get("id", "")
    query = (
        "SELECT id, username, email, role, is_active FROM users "
        "WHERE id = ?"
    )
    params = (user_id,)
    print(f"[SECURE QUERY] {query} | params={params!r}")

    conn = get_db()
    try:
        rows = conn.cursor().execute(query, params).fetchall()
    except Exception:
        app.logger.exception("DB error in secure profile")
        return "Something went wrong", 500
    finally:
        conn.close()

    return render_template("secure/profile.html", users=rows, query_text=user_id)


# ===================================================================
#  ATTACK DASHBOARD
# ===================================================================


@app.route("/attacks")
def attacks_dashboard():
    return render_template("attacks.html", attacks=ATTACKS)


@app.route("/attacks/launch/<int:attack_id>", methods=["POST"])
def launch_attack(attack_id: int):
    attack = next((a for a in ATTACKS if a["id"] == attack_id), None)
    if attack is None:
        abort(404, "Unknown attack id")

    if attack["action"] == "search_get":
        return redirect(url_for("vuln_search", q=attack["payload"]))

    if attack["action"] == "profile_get":
        return redirect(url_for("vuln_profile", id=attack["payload"]))

    if attack["action"] == "login_post":
        return render_template(
            "auto_submit.html",
            attack_name=attack["name"],
            target=url_for("vuln_login"),
            fields={
                "username": attack["payload"],
                "password": attack.get("password", "anything"),
            },
        )

    abort(500, "Attack action not configured")


# ===================================================================
#  COMPARE PAGE
# ===================================================================


@app.route("/compare")
def compare():
    return render_template("compare.html", cases=build_compare_cases())


# ===================================================================
#  ADMIN – User Management
# ===================================================================


@app.route("/admin/users")
def admin_users():
    conn = get_db()
    try:
        users = conn.cursor().execute(
            "SELECT id, username, password, email, role, is_active FROM users ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/add", methods=["POST"])
def admin_add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "user").strip()

    if not username or not password or not email:
        flash("All fields are required.", "error")
        return redirect(url_for("admin_users"))

    conn = get_db()
    try:
        conn.cursor().execute(
            "INSERT INTO users (username, password, email, role, is_active) VALUES (?, ?, ?, ?, 1)",
            (username, password, email, role),
        )
        conn.commit()
        flash(f"User '{username}' added successfully.", "success")
    except sqlite3.IntegrityError:
        flash(f"Username or email already exists.", "error")
    except Exception as exc:
        flash(f"Error: {exc}", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id: int):
    conn = get_db()
    try:
        conn.cursor().execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash("User deleted.", "success")
    finally:
        conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/reset", methods=["POST"])
def admin_reset_db():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users")
        cur.execute("DELETE FROM products")
        cur.executemany(
            "INSERT INTO users (username, password, email, role, is_active) VALUES (?, ?, ?, ?, ?)",
            [
                ("admin", "Adm1n@2026!", "admin@example.com", "admin", 1),
                ("alice", "Alice#Pass91", "alice@example.com", "user", 1),
                ("bob", "Bob$Secure42", "bob@example.com", "user", 1),
                ("charlie", "Ch@rlie7788", "charlie@example.com", "user", 1),
            ],
        )
        cur.executemany(
            "INSERT INTO products (name, price, category, secret_code) VALUES (?, ?, ?, ?)",
            [
                ("Zero-Day Hoodie", 59.99, "Apparel", "INTERNAL-001"),
                ("Packet Sniffer Mug", 14.50, "Accessories", "INTERNAL-002"),
                ("Red Team Notebook", 9.99, "Stationery", "INTERNAL-003"),
                ("Firewall Sticker Pack", 6.25, "Accessories", "INTERNAL-004"),
                ("SOC Analyst Keyboard", 79.00, "Electronics", "INTERNAL-005"),
                ("Threat Intel Poster", 22.75, "Decor", "INTERNAL-006"),
            ],
        )
        conn.commit()
        flash("Database reset to defaults.", "success")
    finally:
        conn.close()
    return redirect(url_for("admin_users"))


# ===================================================================
#  Logout
# ===================================================================


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ===================================================================
#  Run
# ===================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
