"""Shared Postgres connection pool.

Only IAM and S3 use this (EC2/VPC stay in-memory, per-process). Every other
module that needs the database imports `get_conn`/`is_configured` from here
rather than managing its own connection — keeps pooling and the
DATABASE_URL env var in exactly one place.
"""
import os
import contextlib

_pool = None
_DATABASE_URL_ENV = "DATABASE_URL"


def is_configured():
    return bool(os.environ.get(_DATABASE_URL_ENV))


def _get_pool():
    global _pool
    if _pool is None:
        import psycopg2.pool
        dsn = os.environ.get(_DATABASE_URL_ENV)
        if not dsn:
            raise RuntimeError(
                f"{_DATABASE_URL_ENV} is not set. IAM user/key management and the S3 "
                "service both require Postgres; set DATABASE_URL "
                "(e.g. postgresql://user:pass@host:5432/aws_emulator) or run in a mode "
                "that doesn't need them."
            )
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 10, dsn)
    return _pool


@contextlib.contextmanager
def get_conn():
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)
