import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "users.db"

USERS = [
    ("admin", "Adm1n@2026!", "admin@example.com", "admin", 1),
    ("alice", "Alice#Pass91", "alice@example.com", "user", 1),
    ("bob", "Bob$Secure42", "bob@example.com", "user", 1),
    ("charlie", "Ch@rlie7788", "charlie@example.com", "user", 1),
]

PRODUCTS = [
    ("Zero-Day Hoodie", 59.99, "Apparel", "INTERNAL-001"),
    ("Packet Sniffer Mug", 14.50, "Accessories", "INTERNAL-002"),
    ("Red Team Notebook", 9.99, "Stationery", "INTERNAL-003"),
    ("Firewall Sticker Pack", 6.25, "Accessories", "INTERNAL-004"),
    ("SOC Analyst Keyboard", 79.00, "Electronics", "INTERNAL-005"),
    ("Threat Intel Poster", 22.75, "Decor", "INTERNAL-006"),
]


def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    print(f"[OK] Connected to database: {DB_PATH}")

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL CHECK (price >= 0),
            category TEXT NOT NULL,
            secret_code TEXT NOT NULL
        );
        """
    )
    print("[OK] Ensured tables exist: users, products")

    cur.execute("DELETE FROM users;")
    cur.execute("DELETE FROM products;")
    print("[OK] Cleared existing data")

    cur.executemany(
        """
        INSERT INTO users (username, password, email, role, is_active)
        VALUES (?, ?, ?, ?, ?);
        """,
        USERS,
    )
    print(f"[OK] Seeded users table with {len(USERS)} rows")

    cur.executemany(
        """
        INSERT INTO products (name, price, category, secret_code)
        VALUES (?, ?, ?, ?);
        """,
        PRODUCTS,
    )
    print(f"[OK] Seeded products table with {len(PRODUCTS)} rows")

    conn.commit()
    conn.close()
    print("[OK] Database setup completed successfully")


if __name__ == "__main__":
    main()
