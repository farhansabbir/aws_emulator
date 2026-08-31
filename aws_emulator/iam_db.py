"""IAM data access: users + long-term access keys, backed by Postgres.

Deliberately narrow scope: identities and credentials only. No groups,
roles, policy documents, or authorization evaluation - this exists to give
S3's SigV4 verification something real to check credentials against, not to
be a policy engine.
"""
import os
import uuid
import secrets
import datetime

import db

DEFAULT_SEED_USER = "emulator"
DEFAULT_SEED_ACCESS_KEY = "test"
DEFAULT_SEED_SECRET_KEY = "test"


def account_id():
    return os.environ.get("EMULATOR_ACCOUNT_ID", "123456789012")


def user_arn(user_name, path="/"):
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path = path + "/"
    return f"arn:aws:iam::{account_id()}:user{path}{user_name}"


def _new_user_id():
    return "AIDA" + uuid.uuid4().hex[:17].upper()


def _new_access_key_id():
    return "AKIA" + uuid.uuid4().hex[:16].upper()


def _new_secret_key():
    return secrets.token_urlsafe(30)[:40]


# Arbitrary constant, just needs to be unique per schema-owning module so
# concurrent callers (multiple gunicorn workers in one process, or multiple
# container replicas at cold start) serialize on schema creation instead of
# racing CREATE TABLE IF NOT EXISTS against Postgres's catalog (which is
# NOT safe under concurrency - two racing creates can both pass the "does
# it exist" check and then collide on pg_type, crashing the loser).
_SCHEMA_LOCK_ID = 727271001


def init_schema():
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS iam_users (
                    user_name TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    arn TEXT NOT NULL,
                    path TEXT NOT NULL DEFAULT '/',
                    create_date TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS iam_access_keys (
                    access_key_id TEXT PRIMARY KEY,
                    user_name TEXT NOT NULL REFERENCES iam_users(user_name) ON DELETE CASCADE,
                    secret_access_key TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Active',
                    create_date TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute("SELECT COUNT(*) FROM iam_users")
            (count,) = cur.fetchone()
            if count == 0:
                cur.execute(
                    "INSERT INTO iam_users (user_name, user_id, arn, path) VALUES (%s, %s, %s, %s)",
                    (DEFAULT_SEED_USER, _new_user_id(), user_arn(DEFAULT_SEED_USER), "/"),
                )
                cur.execute(
                    "INSERT INTO iam_access_keys (access_key_id, user_name, secret_access_key, status) VALUES (%s, %s, %s, %s)",
                    (DEFAULT_SEED_ACCESS_KEY, DEFAULT_SEED_USER, DEFAULT_SEED_SECRET_KEY, "Active"),
                )


def create_user(user_name, path="/"):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO iam_users (user_name, user_id, arn, path) VALUES (%s, %s, %s, %s) RETURNING user_name, user_id, arn, path, create_date",
                (user_name, _new_user_id(), user_arn(user_name, path), path),
            )
            return _row_to_user(cur.fetchone())


def get_user(user_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_name, user_id, arn, path, create_date FROM iam_users WHERE user_name = %s",
                (user_name,),
            )
            row = cur.fetchone()
            return _row_to_user(row) if row else None


def list_users():
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_name, user_id, arn, path, create_date FROM iam_users ORDER BY user_name")
            return [_row_to_user(r) for r in cur.fetchall()]


def delete_user(user_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM iam_users WHERE user_name = %s", (user_name,))
            return cur.rowcount > 0


def create_access_key(user_name):
    access_key_id = _new_access_key_id()
    secret = _new_secret_key()
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO iam_access_keys (access_key_id, user_name, secret_access_key, status) VALUES (%s, %s, %s, 'Active') RETURNING access_key_id, user_name, secret_access_key, status, create_date",
                (access_key_id, user_name, secret),
            )
            return _row_to_key(cur.fetchone())


def list_access_keys(user_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT access_key_id, user_name, secret_access_key, status, create_date FROM iam_access_keys WHERE user_name = %s ORDER BY create_date",
                (user_name,),
            )
            return [_row_to_key(r) for r in cur.fetchall()]


def delete_access_key(access_key_id, user_name=None):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if user_name:
                cur.execute("DELETE FROM iam_access_keys WHERE access_key_id = %s AND user_name = %s", (access_key_id, user_name))
            else:
                cur.execute("DELETE FROM iam_access_keys WHERE access_key_id = %s", (access_key_id,))
            return cur.rowcount > 0


def update_access_key(access_key_id, status):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE iam_access_keys SET status = %s WHERE access_key_id = %s", (status, access_key_id))
            return cur.rowcount > 0


def get_credential(access_key_id):
    """Returns (user_name, secret_access_key, status) for signature verification, or None."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_name, secret_access_key, status FROM iam_access_keys WHERE access_key_id = %s",
                (access_key_id,),
            )
            row = cur.fetchone()
            return tuple(row) if row else None


def _row_to_user(row):
    user_name, user_id, arn, path, create_date = row
    return {"user_name": user_name, "user_id": user_id, "arn": arn, "path": path, "create_date": _iso(create_date)}


def _row_to_key(row):
    access_key_id, user_name, secret_access_key, status, create_date = row
    return {
        "access_key_id": access_key_id,
        "user_name": user_name,
        "secret_access_key": secret_access_key,
        "status": status,
        "create_date": _iso(create_date),
    }


def _iso(dt):
    if isinstance(dt, datetime.datetime):
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return dt
