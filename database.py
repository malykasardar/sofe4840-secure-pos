"""
database.py
Owner: Abdallah Hanoosh (100749026)
"""

import sqlite3
from datetime import datetime
import config


def get_db():
    conn = sqlite3.connect(config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            username              TEXT UNIQUE NOT NULL,
            password_hash         TEXT NOT NULL,
            role                  TEXT NOT NULL,
            public_key            TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            order_uid            TEXT UNIQUE NOT NULL,
            purchaser_id         INTEGER NOT NULL,
            supervisor_id        INTEGER,
            status               TEXT NOT NULL DEFAULT 'pending',
            encrypted_payload    TEXT NOT NULL,
            purchaser_signature  TEXT NOT NULL,
            purchaser_timestamp  TEXT NOT NULL,
            supervisor_signature TEXT,
            supervisor_timestamp TEXT,
            created_at           TEXT NOT NULL,
            updated_at           TEXT NOT NULL,
            order_meta           TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            action     TEXT NOT NULL,
            order_id   TEXT,
            timestamp  TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def insert_user(username, password_hash, role, public_key, encrypted_private_key):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, public_key, encrypted_private_key) VALUES (?,?,?,?,?)",
        (username, password_hash, role, public_key, encrypted_private_key)
    )
    conn.commit()
    conn.close()


def get_first_user_by_role(role):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE role = ? LIMIT 1", (role,)).fetchone()
    conn.close()
    return user


def get_supervisor():
    return get_first_user_by_role("supervisor")


def get_orders_dept_user():
    return get_first_user_by_role("orders_dept")


def insert_order(order_uid, purchaser_id, supervisor_id, encrypted_payload,
                 purchaser_signature, purchaser_timestamp, status, created_at, order_meta=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO orders (order_uid, purchaser_id, supervisor_id, encrypted_payload, "
        "purchaser_signature, purchaser_timestamp, status, created_at, updated_at, order_meta) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (order_uid, purchaser_id, supervisor_id, encrypted_payload,
         purchaser_signature, purchaser_timestamp, status, created_at, created_at, order_meta)
    )
    conn.commit()
    conn.close()


def get_order(order_id):
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    return order


def get_orders_by_purchaser(purchaser_id):
    conn = get_db()
    orders = conn.execute(
        "SELECT * FROM orders WHERE purchaser_id = ? ORDER BY created_at DESC", (purchaser_id,)
    ).fetchall()
    conn.close()
    return orders


def get_orders_by_supervisor(supervisor_id):
    conn = get_db()
    orders = conn.execute(
        "SELECT * FROM orders WHERE supervisor_id = ? AND status = 'pending' ORDER BY created_at DESC",
        (supervisor_id,)
    ).fetchall()
    conn.close()
    return orders


def get_approved_orders():
    conn = get_db()
    orders = conn.execute(
        "SELECT * FROM orders WHERE status = 'approved' ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return orders


_ALLOWED_ORDER_UPDATE_FIELDS = {
    "status", "encrypted_payload",
    "supervisor_signature", "supervisor_timestamp",
}

def update_order(order_id, **fields):
    invalid = set(fields) - _ALLOWED_ORDER_UPDATE_FIELDS
    if invalid:
        raise ValueError(f"update_order: disallowed fields: {invalid}")
    fields["updated_at"] = datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [order_id]
    conn = get_db()
    conn.execute(f"UPDATE orders SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()


def write_audit_log(user_id, action, order_id=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (user_id, action, order_id, timestamp) VALUES (?,?,?,?)",
        (user_id, action, order_id, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
