"""Object bytes on the shared volume (S3_DATA_DIR). Metadata lives in
Postgres (s3_db.py); this module only ever deals in bytes and paths.

One file per object version - never overwritten - so old versions stay
retrievable for as long as their s3_objects row exists.
"""
import hashlib
import os
import shutil
import uuid


def data_dir():
    return os.environ.get("S3_DATA_DIR", "/data/objects")


def _abs(rel_path):
    return os.path.join(data_dir(), rel_path)


def write_object(bucket, key, data):
    """Writes `data` under a fresh, never-reused relative path. Returns
    (storage_path, etag, size)."""
    rel_dir = os.path.join("objects", bucket)
    os.makedirs(_abs(rel_dir), exist_ok=True)
    rel_path = os.path.join(rel_dir, uuid.uuid4().hex)
    with open(_abs(rel_path), "wb") as f:
        f.write(data)
    etag = hashlib.md5(data).hexdigest()
    return rel_path, etag, len(data)


def read_object(storage_path):
    with open(_abs(storage_path), "rb") as f:
        return f.read()


def delete_object(storage_path):
    if not storage_path:
        return
    try:
        os.remove(_abs(storage_path))
    except FileNotFoundError:
        pass


def write_part(upload_id, part_number, data):
    rel_dir = os.path.join(".multipart", upload_id)
    os.makedirs(_abs(rel_dir), exist_ok=True)
    rel_path = os.path.join(rel_dir, str(part_number))
    with open(_abs(rel_path), "wb") as f:
        f.write(data)
    etag = hashlib.md5(data).hexdigest()
    return rel_path, etag, len(data)


def concatenate_parts(bucket, key, part_storage_paths):
    """Streams parts (in the given order) into one final object file.
    Returns (storage_path, etag, size)."""
    rel_dir = os.path.join("objects", bucket)
    os.makedirs(_abs(rel_dir), exist_ok=True)
    rel_path = os.path.join(rel_dir, uuid.uuid4().hex)
    md5 = hashlib.md5()
    size = 0
    with open(_abs(rel_path), "wb") as out:
        for part_path in part_storage_paths:
            with open(_abs(part_path), "rb") as pf:
                while True:
                    chunk = pf.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    md5.update(chunk)
                    size += len(chunk)
    return rel_path, md5.hexdigest(), size


def multipart_etag(part_etags):
    """S3's convention for a completed multipart object's ETag: the hex MD5
    of the concatenated *binary* MD5 digests of each part, suffixed with
    "-<part count>"."""
    combined = hashlib.md5()
    for etag in part_etags:
        combined.update(bytes.fromhex(etag.strip('"')))
    return f"{combined.hexdigest()}-{len(part_etags)}"


def delete_multipart_temp(upload_id):
    shutil.rmtree(_abs(os.path.join(".multipart", upload_id)), ignore_errors=True)
