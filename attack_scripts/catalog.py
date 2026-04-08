import json
import re
import sqlite3
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT_DIR / "attacks.json"
DB_PATH = ROOT_DIR / "users.db"
TEMPLATE_PATTERN = re.compile(r"{([A-Za-z_][A-Za-z0-9_]*)}")


def _load_context() -> dict:
    usernames = []
    admin_username = None

    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        try:
            rows = conn.execute("SELECT username, role FROM users ORDER BY id").fetchall()
        finally:
            conn.close()

        usernames = [row[0] for row in rows]
        admin_username = next((row[0] for row in rows if row[1] == "admin"), None)

    if admin_username is None:
        admin_username = usernames[0] if usernames else "admin"

    return {
        "admin_username": admin_username,
        "first_username": usernames[0] if usernames else admin_username,
    }


def _resolve_template(value: str, context: dict) -> str:
    def replace(match):
        key = match.group(1)
        return str(context.get(key, match.group(0)))

    return TEMPLATE_PATTERN.sub(replace, value)


def load_attack(attack_id: int) -> dict:
    if not CATALOG_PATH.exists():
        raise RuntimeError(f"Attack catalog not found: {CATALOG_PATH}")

    with CATALOG_PATH.open("r", encoding="utf-8") as fh:
        raw_attacks = json.load(fh)

    if not isinstance(raw_attacks, list):
        raise RuntimeError("Attack catalog must be a JSON list.")

    raw_attack = next(
        (
            item
            for item in raw_attacks
            if isinstance(item, dict) and isinstance(item.get("id"), int) and item["id"] == attack_id
        ),
        None,
    )
    if raw_attack is None:
        raise RuntimeError(f"Attack id {attack_id} not found in catalog.")

    context = _load_context()
    payload_raw = raw_attack.get("payload_template", raw_attack.get("payload"))
    if not isinstance(payload_raw, str) or not payload_raw:
        raise RuntimeError(f"Attack {attack_id} has no payload.")

    password_raw = raw_attack.get("password_template", raw_attack.get("password", "anything"))
    if not isinstance(password_raw, str):
        password_raw = str(password_raw)

    return {
        "id": raw_attack["id"],
        "name": raw_attack.get("name", f"Attack {attack_id}"),
        "action": raw_attack.get("action", ""),
        "payload": _resolve_template(payload_raw, context),
        "password": _resolve_template(password_raw, context),
    }
