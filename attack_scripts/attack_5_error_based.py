import requests


LOGIN_URL = "http://127.0.0.1:5000/vulnerable/login"


def main() -> None:
    data = {"username": "'", "password": "anything"}

    try:
        response = requests.post(LOGIN_URL, data=data, timeout=5)
    except requests.RequestException as exc:
        print(f"[ERROR] Request failed: {exc}")
        return

    print(f"Target: {LOGIN_URL}")
    print("Payload username: \"'\"")
    print(f"Status: {response.status_code}")
    print("\nResponse body:")
    print(response.text)


if __name__ == "__main__":
    main()
