# SQL Injection Demo Lab

An interactive cybersecurity education tool that demonstrates **6 types of SQL injection attacks** and shows how each one is prevented using parameterized queries, input validation, and rate limiting.

## Features

| Section | Description |
|---------|-------------|
| **Vulnerable App** | Routes using raw string concatenation — every injection works |
| **Secure App** | Same routes using parameterized queries + input validation — attacks blocked |
| **Attack Dashboard** | One-click launch for all 6 attack payloads |
| **Query Comparison** | Side-by-side view of vulnerable vs parameterized queries |
| **User Management** | Admin panel to add, delete, and reset demo users |

## Attacks Demonstrated

1. **Login Bypass** — `' OR '1'='1' --` bypasses authentication
2. **User Impersonation** — `admin' --` logs in as a specific user
3. **UNION Extraction** — Appends user data to product search results
4. **Boolean Blind** — `1 OR 1=1` dumps all user profiles
5. **Error-Based** — Single quote triggers raw SQL error/traceback
6. **Stacked Query** — `'; DROP TABLE users; --` (conceptual demo)

## Dynamic Attack Catalog

Attack definitions are loaded at runtime from `attacks.json`.

- Dashboard (`/attacks`) reads this catalog on each request.
- Compare page (`/compare`) builds query examples from the same catalog.
- Most CLI scripts in `attack_scripts/` also load payloads from this file.

You can add, remove, or modify attacks in `attacks.json` without changing `app.py`.

## Quick Start (Local)

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd Cyber_Project

# 2. Install dependencies
pip install -r requirements.txt

# 3. Seed the database
python setup_db.py

# 4. Run the app
python app.py
```

Open **http://localhost:5000** in your browser.

## Deployment (Render.com)

1. Push the repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Render auto-detects the `render.yaml` and deploys

## Test Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | Adm1n@2026! | admin |
| alice | Alice#Pass91 | user |
| bob | Bob$Secure42 | user |
| charlie | Ch@rlie7788 | user |

## Attack Scripts (CLI)

```bash
cd attack_scripts
python run_all_attacks.py    # Interactive menu
python attack_1_login_bypass.py   # Individual attack
```

## Tech Stack

- **Backend**: Python / Flask
- **Database**: SQLite
- **Server**: Gunicorn (production)
- **Deployment**: Render.com (free tier)

## Disclaimer

This project is for **educational purposes only**. The vulnerable endpoints are intentionally insecure. Do not deploy to production or use in a real application.

---

*Built for NMIMS Cybersecurity Project*
