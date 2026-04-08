from catalog import load_attack


LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"


def build_vulnerable_query(username: str, password: str) -> str:
    return (
        "SELECT id, username, role, is_active FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )


def main() -> None:
    attack = load_attack(6)
    username_payload = attack["payload"]
    password = attack.get("password", "anything")
    query = build_vulnerable_query(username_payload, password)

    print(f"Target login route: {LOGIN_URL}")
    print(f"Username payload: {username_payload!r}")
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
