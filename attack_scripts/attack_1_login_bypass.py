import requests

from catalog import load_attack

LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"

def try_payload(payload: str, password: str) -> None:
    data = {"username": payload, "password": password}

    try:
        response = requests.post(LOGIN_URL, data=data, allow_redirects=False, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] Payload {payload!r} -> request failed: {exc}")
        return

    location = response.headers.get("Location", "")
    redirected_to_dashboard = response.is_redirect and location.endswith("/dashboard")

    if redirected_to_dashboard:
        print(f"[SUCCESS] Payload {payload!r} -> redirected to /dashboard")
        return

    if response.status_code == 200:
        print(f"[FAILURE] Payload {payload!r} -> login page returned (status 200)")
    else:
        print(
            f"[FAILURE] Payload {payload!r} -> status {response.status_code}, "
            f"Location={location!r}"
        )


def main() -> None:
    attack = load_attack(1)
    payload = attack["payload"]
    password = attack.get("password", "anything")

    print(f"Target: {LOGIN_URL}")
    print(f"Configured payload: {payload!r}")
    try_payload(payload, password)


if __name__ == "__main__":
    main()
