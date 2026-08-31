"""S3 metadata store: buckets + objects + multipart uploads, in Postgres.

Object bytes never live here - see s3_storage.py for the shared-volume
byte storage this table's `storage_path` columns point into.
"""
import datetime
import uuid

from psycopg2.extras import Json

import db

_SCHEMA_LOCK_ID = 727271002

BUCKET_FIELDS = ("tags", "acl", "policy", "cors", "encryption", "public_access_block", "website")


def init_schema():
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS s3_buckets (
                    bucket_name TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    region TEXT NOT NULL DEFAULT 'us-east-1',
                    create_date TIMESTAMPTZ NOT NULL DEFAULT now(),
                    versioning_status TEXT NOT NULL DEFAULT 'Disabled',
                    tags JSONB,
                    acl JSONB,
                    policy JSONB,
                    cors JSONB,
                    encryption JSONB,
                    public_access_block JSONB,
                    website JSONB
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS s3_objects (
                    id BIGSERIAL PRIMARY KEY,
                    bucket_name TEXT NOT NULL REFERENCES s3_buckets(bucket_name) ON DELETE CASCADE,
                    object_key TEXT NOT NULL,
                    version_id TEXT NOT NULL DEFAULT 'null',
                    is_latest BOOLEAN NOT NULL DEFAULT true,
                    is_delete_marker BOOLEAN NOT NULL DEFAULT false,
                    size BIGINT NOT NULL DEFAULT 0,
                    etag TEXT,
                    content_type TEXT,
                    storage_path TEXT,
                    tags JSONB,
                    metadata JSONB,
                    last_modified TIMESTAMPTZ NOT NULL DEFAULT now(),
                    UNIQUE (bucket_name, object_key, version_id)
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_s3_objects_latest ON s3_objects (bucket_name, object_key) WHERE is_latest")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS s3_multipart_uploads (
                    upload_id TEXT PRIMARY KEY,
                    bucket_name TEXT NOT NULL,
                    object_key TEXT NOT NULL,
                    content_type TEXT,
                    initiated TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS s3_multipart_parts (
                    upload_id TEXT NOT NULL REFERENCES s3_multipart_uploads(upload_id) ON DELETE CASCADE,
                    part_number INT NOT NULL,
                    etag TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    storage_path TEXT NOT NULL,
                    PRIMARY KEY (upload_id, part_number)
                )
                """
            )


def _iso(dt):
    if isinstance(dt, datetime.datetime):
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return dt


# ---------------------------------------------------------------- buckets --

def create_bucket(bucket_name, owner, region="us-east-1"):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO s3_buckets (bucket_name, owner, region) VALUES (%s, %s, %s)",
                (bucket_name, owner, region),
            )


def get_bucket(bucket_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT bucket_name, owner, region, create_date, versioning_status FROM s3_buckets WHERE bucket_name = %s",
                (bucket_name,),
            )
            row = cur.fetchone()
            if not row:
                return None
            name, owner, region, create_date, versioning = row
            return {"bucket_name": name, "owner": owner, "region": region, "create_date": _iso(create_date), "versioning_status": versioning}


def list_buckets(owner=None):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if owner:
                cur.execute("SELECT bucket_name, create_date FROM s3_buckets WHERE owner = %s ORDER BY bucket_name", (owner,))
            else:
                cur.execute("SELECT bucket_name, create_date FROM s3_buckets ORDER BY bucket_name")
            return [{"bucket_name": n, "create_date": _iso(d)} for n, d in cur.fetchall()]


def delete_bucket(bucket_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM s3_buckets WHERE bucket_name = %s", (bucket_name,))
            return cur.rowcount > 0


def bucket_object_count(bucket_name):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM s3_objects WHERE bucket_name = %s", (bucket_name,))
            (count,) = cur.fetchone()
            return count


def set_versioning(bucket_name, status):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE s3_buckets SET versioning_status = %s WHERE bucket_name = %s", (status, bucket_name))


def set_bucket_field(bucket_name, field, value):
    assert field in BUCKET_FIELDS
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE s3_buckets SET {field} = %s WHERE bucket_name = %s", (Json(value), bucket_name))


def get_bucket_field(bucket_name, field):
    assert field in BUCKET_FIELDS
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {field} FROM s3_buckets WHERE bucket_name = %s", (bucket_name,))
            row = cur.fetchone()
            return row[0] if row else None


def clear_bucket_field(bucket_name, field):
    assert field in BUCKET_FIELDS
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE s3_buckets SET {field} = NULL WHERE bucket_name = %s", (bucket_name,))


# ---------------------------------------------------------------- objects --

def _row_to_object(row):
    (obj_id, bucket, key, version_id, is_latest, is_delete_marker, size, etag,
     content_type, storage_path, tags, metadata, last_modified) = row
    return {
        "id": obj_id, "bucket_name": bucket, "object_key": key, "version_id": version_id,
        "is_latest": is_latest, "is_delete_marker": is_delete_marker, "size": size, "etag": etag,
        "content_type": content_type, "storage_path": storage_path, "tags": tags or {},
        "metadata": metadata or {}, "last_modified": _iso(last_modified),
    }


_OBJ_COLS = "id, bucket_name, object_key, version_id, is_latest, is_delete_marker, size, etag, content_type, storage_path, tags, metadata, last_modified"


def put_object(bucket_name, key, size, etag, content_type, storage_path, tags=None, metadata=None, versioned=False):
    """Writes a new object version. If `versioned` is False, upserts the
    single 'null'-version row (real S3 semantics for un-versioned buckets)."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if versioned:
                version_id = uuid.uuid4().hex
                cur.execute(
                    "UPDATE s3_objects SET is_latest = false WHERE bucket_name = %s AND object_key = %s AND is_latest",
                    (bucket_name, key),
                )
                cur.execute(
                    f"""INSERT INTO s3_objects (bucket_name, object_key, version_id, is_latest, is_delete_marker, size, etag, content_type, storage_path, tags, metadata)
                        VALUES (%s, %s, %s, true, false, %s, %s, %s, %s, %s, %s)
                        RETURNING {_OBJ_COLS}""",
                    (bucket_name, key, version_id, size, etag, content_type, storage_path, Json(tags or {}), Json(metadata or {})),
                )
            else:
                version_id = "null"
                cur.execute(
                    f"""INSERT INTO s3_objects (bucket_name, object_key, version_id, is_latest, is_delete_marker, size, etag, content_type, storage_path, tags, metadata)
                        VALUES (%s, %s, 'null', true, false, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (bucket_name, object_key, version_id) DO UPDATE SET
                            size = EXCLUDED.size, etag = EXCLUDED.etag, content_type = EXCLUDED.content_type,
                            storage_path = EXCLUDED.storage_path, tags = EXCLUDED.tags, metadata = EXCLUDED.metadata,
                            last_modified = now(), is_delete_marker = false
                        RETURNING {_OBJ_COLS}""",
                    (bucket_name, key, size, etag, content_type, storage_path, Json(tags or {}), Json(metadata or {})),
                )
            return _row_to_object(cur.fetchone())


def get_object(bucket_name, key, version_id=None):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if version_id:
                cur.execute(f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s AND object_key = %s AND version_id = %s", (bucket_name, key, version_id))
            else:
                cur.execute(f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s AND object_key = %s AND is_latest", (bucket_name, key))
            row = cur.fetchone()
            return _row_to_object(row) if row else None


def list_object_versions(bucket_name, key):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s AND object_key = %s ORDER BY last_modified DESC", (bucket_name, key))
            return [_row_to_object(r) for r in cur.fetchall()]


def list_all_versions(bucket_name, prefix=None, max_keys=1000):
    """Every version of every object in the bucket (ListObjectVersions),
    ordered the way S3 returns them: by key, then newest-first."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            sql = f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s"
            params = [bucket_name]
            if prefix:
                sql += " AND object_key LIKE %s"
                params.append(prefix.replace("%", r"\%").replace("_", r"\_") + "%")
            sql += " ORDER BY object_key, last_modified DESC LIMIT %s"
            params.append(max_keys)
            cur.execute(sql, params)
            return [_row_to_object(r) for r in cur.fetchall()]


def delete_object_version(bucket_name, key, version_id):
    """Hard-deletes one version row and, if it was the latest, promotes the
    next most recent remaining version. Returns the deleted row (for byte
    cleanup) or None if it didn't exist."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s AND object_key = %s AND version_id = %s", (bucket_name, key, version_id))
            row = cur.fetchone()
            if not row:
                return None
            deleted = _row_to_object(row)
            cur.execute("DELETE FROM s3_objects WHERE bucket_name = %s AND object_key = %s AND version_id = %s", (bucket_name, key, version_id))
            if deleted["is_latest"]:
                cur.execute(
                    "SELECT version_id FROM s3_objects WHERE bucket_name = %s AND object_key = %s ORDER BY last_modified DESC LIMIT 1",
                    (bucket_name, key),
                )
                nxt = cur.fetchone()
                if nxt:
                    cur.execute(
                        "UPDATE s3_objects SET is_latest = true WHERE bucket_name = %s AND object_key = %s AND version_id = %s",
                        (bucket_name, key, nxt[0]),
                    )
            return deleted


def add_delete_marker(bucket_name, key):
    version_id = uuid.uuid4().hex
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE s3_objects SET is_latest = false WHERE bucket_name = %s AND object_key = %s AND is_latest",
                (bucket_name, key),
            )
            cur.execute(
                f"""INSERT INTO s3_objects (bucket_name, object_key, version_id, is_latest, is_delete_marker, size, storage_path)
                    VALUES (%s, %s, %s, true, true, 0, NULL) RETURNING {_OBJ_COLS}""",
                (bucket_name, key, version_id),
            )
            return _row_to_object(cur.fetchone())


def set_object_tags(bucket_name, key, version_id, tags):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if version_id:
                cur.execute("UPDATE s3_objects SET tags = %s WHERE bucket_name = %s AND object_key = %s AND version_id = %s", (Json(tags), bucket_name, key, version_id))
            else:
                cur.execute("UPDATE s3_objects SET tags = %s WHERE bucket_name = %s AND object_key = %s AND is_latest", (Json(tags), bucket_name, key))


def list_objects(bucket_name, prefix=None, delimiter=None, start_after=None, max_keys=1000):
    """Returns (objects, common_prefixes) for the current (is_latest,
    non-delete-marker) objects, applying prefix/delimiter grouping the way
    ListObjects(V2) does."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            sql = f"SELECT {_OBJ_COLS} FROM s3_objects WHERE bucket_name = %s AND is_latest AND NOT is_delete_marker"
            params = [bucket_name]
            if prefix:
                sql += " AND object_key LIKE %s"
                params.append(prefix.replace("%", r"\%").replace("_", r"\_") + "%")
            if start_after:
                sql += " AND object_key > %s"
                params.append(start_after)
            sql += " ORDER BY object_key"
            cur.execute(sql, params)
            rows = [_row_to_object(r) for r in cur.fetchall()]

    if not delimiter:
        return rows[:max_keys], []

    objects = []
    prefixes = set()
    prefix = prefix or ""
    for obj in rows:
        rest = obj["object_key"][len(prefix):]
        if delimiter in rest:
            common = prefix + rest.split(delimiter, 1)[0] + delimiter
            prefixes.add(common)
        else:
            objects.append(obj)
        if len(objects) + len(prefixes) >= max_keys:
            break
    return objects, sorted(prefixes)


# ---------------------------------------------------------- multipart api --

def create_multipart_upload(bucket_name, key, content_type):
    upload_id = uuid.uuid4().hex
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO s3_multipart_uploads (upload_id, bucket_name, object_key, content_type) VALUES (%s, %s, %s, %s)",
                (upload_id, bucket_name, key, content_type),
            )
    return upload_id


def get_multipart_upload(upload_id):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT upload_id, bucket_name, object_key, content_type FROM s3_multipart_uploads WHERE upload_id = %s", (upload_id,))
            row = cur.fetchone()
            if not row:
                return None
            uid, bucket, key, content_type = row
            return {"upload_id": uid, "bucket_name": bucket, "object_key": key, "content_type": content_type}


def add_part(upload_id, part_number, etag, size, storage_path):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO s3_multipart_parts (upload_id, part_number, etag, size, storage_path)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (upload_id, part_number) DO UPDATE SET etag = EXCLUDED.etag, size = EXCLUDED.size, storage_path = EXCLUDED.storage_path""",
                (upload_id, part_number, etag, size, storage_path),
            )


def list_parts(upload_id):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT part_number, etag, size, storage_path FROM s3_multipart_parts WHERE upload_id = %s ORDER BY part_number", (upload_id,))
            return [{"part_number": p, "etag": e, "size": s, "storage_path": sp} for p, e, s, sp in cur.fetchall()]


def abort_multipart_upload(upload_id):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM s3_multipart_uploads WHERE upload_id = %s", (upload_id,))


def complete_multipart_upload(upload_id):
    abort_multipart_upload(upload_id)  # cascades to s3_multipart_parts
