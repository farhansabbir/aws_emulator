"""S3 REST API (mode: s3, all). Path-style addressing only.

Registered onto the same Flask app as the EC2/IAM query-protocol endpoint
(main.py routes POST-with-Action there; everything else lands here).
"""
import os
import datetime
import email.utils
import xml.etree.ElementTree as ET
from functools import wraps
from urllib.parse import parse_qsl, unquote

import psycopg2.errors
from flask import Blueprint, request, Response

import iam_db
import s3_auth
import s3_db
import s3_storage

bp = Blueprint("s3", __name__)

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_KEYS_DEFAULT = 1000


def register(app):
    import db
    if db.is_configured():
        s3_db.init_schema()
    else:
        app.logger.warning("S3 requires DATABASE_URL to be set; S3 endpoints will error on every request.")
    app.register_blueprint(bp)


# ------------------------------------------------------------------ utils --

def _http_date(iso_str):
    """Our stored/rendered timestamps are ISO 8601 (matching S3's XML
    bodies), but the Last-Modified HTTP *header* requires RFC 7231's
    HTTP-date format (e.g. "Mon, 02 Jan 2006 15:04:05 GMT") - a real SDK's
    response parser rejects anything else."""
    dt = datetime.datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
    return email.utils.format_datetime(dt, usegmt=True)


def _xml(body, status=200, headers=None):
    if not body:
        # A real "no content" success (CreateBucket, PutBucketTagging, ...):
        # an XML declaration with no root element is not valid XML, so send
        # a genuinely empty body rather than a malformed document.
        return Response(status=status, headers=headers or {})
    payload = f'<?xml version="1.0" encoding="UTF-8"?>\n{body}'
    return Response(payload, status=status, headers=headers or {}, mimetype="application/xml")


def _error(code, message, status, bucket=None, key=None):
    extra = ""
    if bucket:
        extra += f"<BucketName>{bucket}</BucketName>"
    if key:
        extra += f"<Key>{key}</Key>"
    body = f"<Error><Code>{code}</Code><Message>{message}</Message>{extra}<RequestId>{os.urandom(8).hex()}</RequestId></Error>"
    return _xml(body, status=status)


def _no_such_bucket(bucket):
    return _error("NoSuchBucket", "The specified bucket does not exist.", 404, bucket=bucket)


def _no_such_key(bucket, key):
    return _error("NoSuchKey", "The specified key does not exist.", 404, bucket=bucket, key=key)


def _require_bucket(bucket):
    b = s3_db.get_bucket(bucket)
    return b


def _requires_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            if s3_auth.auth_enabled():
                identity = s3_auth.verify(request)
            else:
                identity = s3_auth.resolve_identity_unchecked(request)
        except s3_auth.AuthError as e:
            return _error(e.code, e.message, e.status)
        return view(*args, identity=identity, **kwargs)
    return wrapper


def _local_tag(tag):
    """Strips any '{namespace}' prefix ElementTree leaves on tag names, so
    parsing doesn't care whether the client's request XML declared the S3
    xmlns on the root element or not (real clients do; hand-built test
    bodies often don't)."""
    return tag.rsplit("}", 1)[-1]


def _find_local(el, name):
    for child in el:
        if _local_tag(child.tag) == name:
            return child
    return None


def _findall_local(el, name):
    return [child for child in el if _local_tag(child.tag) == name]


def _parse_tagging_header(header_value):
    """x-amz-tagging on PutObject is a URL-encoded query string
    (key1=value1&key2=value2), not XML - separate from the ?tagging
    sub-resource's XML body."""
    if not header_value:
        return {}
    return dict(parse_qsl(header_value, keep_blank_values=True))


def _tagging_to_dict(xml_body):
    if not xml_body:
        return {}
    root = ET.fromstring(xml_body)
    tagset = _find_local(root, "TagSet")
    if tagset is None:
        return {}
    tags = {}
    for tag in _findall_local(tagset, "Tag"):
        key_el = _find_local(tag, "Key")
        val_el = _find_local(tag, "Value")
        if key_el is not None:
            tags[key_el.text or ""] = (val_el.text or "") if val_el is not None else ""
    return tags


def _tags_to_xml(tags):
    items = "".join(f"<Tag><Key>{k}</Key><Value>{v}</Value></Tag>" for k, v in (tags or {}).items())
    return f'<Tagging xmlns="{NS}"><TagSet>{items}</TagSet></Tagging>'


def _parse_versioning_status(xml_body):
    root = ET.fromstring(xml_body)
    status_el = _find_local(root, "Status")
    return status_el.text if status_el is not None else "Suspended"


# ---------------------------------------------------------------- buckets --

@bp.route("/", methods=["GET"])
@_requires_auth
def list_buckets(identity):
    access_key_id, user_name = identity
    buckets = s3_db.list_buckets()
    items = "".join(f"<Bucket><Name>{b['bucket_name']}</Name><CreationDate>{b['create_date']}</CreationDate></Bucket>" for b in buckets)
    body = f'<ListAllMyBucketsResult xmlns="{NS}"><Owner><ID>{iam_db.account_id()}</ID><DisplayName>{user_name}</DisplayName></Owner><Buckets>{items}</Buckets></ListAllMyBucketsResult>'
    return _xml(body)


@bp.route("/<bucket>", methods=["PUT"])
@_requires_auth
def bucket_put(bucket, identity):
    access_key_id, user_name = identity
    args = request.args

    existing = s3_db.get_bucket(bucket)

    if "versioning" in args:
        if not existing:
            return _no_such_bucket(bucket)
        status = _parse_versioning_status(request.get_data())
        s3_db.set_versioning(bucket, status)
        return _xml("", status=200)

    for field in ("acl", "policy", "cors", "encryption", "publicAccessBlock", "website"):
        if field in args:
            if not existing:
                return _no_such_bucket(bucket)
            raw = request.get_data().decode("utf-8", errors="replace")
            s3_db.set_bucket_field(bucket, field, {"body": raw})
            return _xml("", status=200)

    if "tagging" in args:
        if not existing:
            return _no_such_bucket(bucket)
        tags = _tagging_to_dict(request.get_data())
        s3_db.set_bucket_field(bucket, "tags", tags)
        return _xml("", status=200)

    # CreateBucket
    if existing:
        if existing["owner"] == user_name:
            return _xml("", status=200, headers={"Location": f"/{bucket}"})
        return _error("BucketAlreadyExists", "The requested bucket name is not available.", 409, bucket=bucket)
    try:
        s3_db.create_bucket(bucket, user_name)
    except psycopg2.errors.UniqueViolation:
        # Lost a create race against another request (possible once S3 runs
        # as multiple replicas) - the bucket exists now either way.
        pass
    return _xml("", status=200, headers={"Location": f"/{bucket}"})


@bp.route("/<bucket>", methods=["DELETE"])
@_requires_auth
def bucket_delete(bucket, identity):
    args = request.args
    existing = s3_db.get_bucket(bucket)
    if not existing:
        return _no_such_bucket(bucket)

    for field in ("tagging", "policy", "cors", "encryption", "publicAccessBlock", "website"):
        if field in args:
            s3_db.clear_bucket_field(bucket, field)
            return Response(status=204)

    if s3_db.bucket_object_count(bucket) > 0:
        return _error("BucketNotEmpty", "The bucket you tried to delete is not empty.", 409, bucket=bucket)
    s3_db.delete_bucket(bucket)
    return Response(status=204)


@bp.route("/<bucket>", methods=["HEAD"])
@_requires_auth
def bucket_head(bucket, identity):
    if not s3_db.get_bucket(bucket):
        return Response(status=404)
    return Response(status=200)


@bp.route("/<bucket>", methods=["GET"])
@_requires_auth
def bucket_get(bucket, identity):
    args = request.args
    existing = s3_db.get_bucket(bucket)
    if not existing:
        return _no_such_bucket(bucket)

    if "location" in args:
        region = existing["region"]
        value = "" if region == "us-east-1" else region
        return _xml(f'<LocationConstraint xmlns="{NS}">{value}</LocationConstraint>')

    if "versioning" in args:
        status = existing["versioning_status"]
        inner = f"<Status>{status}</Status>" if status and status != "Disabled" else ""
        return _xml(f'<VersioningConfiguration xmlns="{NS}">{inner}</VersioningConfiguration>')

    if "tagging" in args:
        tags = s3_db.get_bucket_field(bucket, "tags")
        if not tags:
            return _error("NoSuchTagSet", "The TagSet does not exist.", 404, bucket=bucket)
        return _xml(_tags_to_xml(tags))

    for field, mimetype in (("acl", None), ("policy", "application/json"), ("cors", "application/xml"), ("encryption", "application/xml"), ("publicAccessBlock", "application/xml"), ("website", "application/xml")):
        if field in args:
            stored = s3_db.get_bucket_field(bucket, field)
            if not stored:
                code = {"policy": "NoSuchBucketPolicy", "cors": "NoSuchCORSConfiguration", "encryption": "ServerSideEncryptionConfigurationNotFoundError", "website": "NoSuchWebsiteConfiguration"}.get(field, "NoSuchConfiguration")
                if field == "acl":
                    return _xml(f'<AccessControlPolicy xmlns="{NS}"><Owner><ID>{iam_db.account_id()}</ID></Owner><AccessControlList><Grant><Grantee xsi:type="CanonicalUser"><ID>{iam_db.account_id()}</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>')
                return _error(code, f"The {field} configuration does not exist.", 404, bucket=bucket)
            return Response(stored.get("body", ""), status=200, mimetype=mimetype or "application/xml")

    if "uploads" in args:
        return _xml(f'<ListMultipartUploadsResult xmlns="{NS}"><Bucket>{bucket}</Bucket><Upload/></ListMultipartUploadsResult>')

    if "versions" in args:
        prefix = args.get("prefix")
        max_keys = int(args.get("max-keys", MAX_KEYS_DEFAULT))
        versions = s3_db.list_all_versions(bucket, prefix=prefix, max_keys=max_keys)
        items = []
        for v in versions:
            version_id = v["version_id"]
            is_latest = "true" if v["is_latest"] else "false"
            if v["is_delete_marker"]:
                items.append(f'<DeleteMarker><Key>{v["object_key"]}</Key><VersionId>{version_id}</VersionId><IsLatest>{is_latest}</IsLatest><LastModified>{v["last_modified"]}</LastModified></DeleteMarker>')
            else:
                items.append(
                    f'<Version><Key>{v["object_key"]}</Key><VersionId>{version_id}</VersionId><IsLatest>{is_latest}</IsLatest>'
                    f'<LastModified>{v["last_modified"]}</LastModified><ETag>&quot;{v["etag"]}&quot;</ETag><Size>{v["size"]}</Size><StorageClass>STANDARD</StorageClass></Version>'
                )
        body = f'<ListVersionsResult xmlns="{NS}"><Name>{bucket}</Name><Prefix>{prefix or ""}</Prefix><MaxKeys>{max_keys}</MaxKeys><IsTruncated>false</IsTruncated>{"".join(items)}</ListVersionsResult>'
        return _xml(body)

    # ListObjects / ListObjectsV2
    prefix = args.get("prefix")
    delimiter = args.get("delimiter")
    max_keys = int(args.get("max-keys", MAX_KEYS_DEFAULT))
    is_v2 = args.get("list-type") == "2"
    start_after = args.get("start-after") if is_v2 else args.get("marker")

    objects, prefixes = s3_db.list_objects(bucket, prefix=prefix, delimiter=delimiter, start_after=start_after, max_keys=max_keys)

    contents = "".join(
        f"<Contents><Key>{o['object_key']}</Key><LastModified>{o['last_modified']}</LastModified>"
        f'<ETag>&quot;{o["etag"]}&quot;</ETag><Size>{o["size"]}</Size><StorageClass>STANDARD</StorageClass></Contents>'
        for o in objects
    )
    common = "".join(f"<CommonPrefixes><Prefix>{p}</Prefix></CommonPrefixes>" for p in prefixes)
    count_tag = f"<KeyCount>{len(objects) + len(prefixes)}</KeyCount>" if is_v2 else ""
    body = (
        f'<ListBucketResult xmlns="{NS}"><Name>{bucket}</Name><Prefix>{prefix or ""}</Prefix>'
        f"{count_tag}<MaxKeys>{max_keys}</MaxKeys><IsTruncated>false</IsTruncated>"
        f"{contents}{common}</ListBucketResult>"
    )
    return _xml(body)


@bp.route("/<bucket>", methods=["POST"])
@_requires_auth
def bucket_post(bucket, identity):
    if "delete" in request.args:
        root = ET.fromstring(request.get_data())
        deleted = []
        for obj_el in _findall_local(root, "Object"):
            key_el = _find_local(obj_el, "Key")
            if key_el is None or not key_el.text:
                continue
            key = key_el.text
            version_id_el = _find_local(obj_el, "VersionId")
            version_id = version_id_el.text if version_id_el is not None else None
            _delete_one(bucket, key, version_id)
            deleted.append(key)
        items = "".join(f"<Deleted><Key>{k}</Key></Deleted>" for k in deleted)
        return _xml(f'<DeleteResult xmlns="{NS}">{items}</DeleteResult>')
    return _error("NotImplemented", "Unsupported bucket POST operation.", 501, bucket=bucket)


# ---------------------------------------------------------------- objects --

def _delete_one(bucket, key, version_id):
    existing = s3_db.get_bucket(bucket)
    versioned = bool(existing and existing["versioning_status"] == "Enabled")
    if version_id:
        deleted = s3_db.delete_object_version(bucket, key, version_id)
        if deleted:
            s3_storage.delete_object(deleted["storage_path"])
    elif versioned:
        s3_db.add_delete_marker(bucket, key)
    else:
        current = s3_db.get_object(bucket, key)
        if current:
            s3_db.delete_object_version(bucket, key, current["version_id"])
            s3_storage.delete_object(current["storage_path"])


@bp.route("/<bucket>/<path:key>", methods=["PUT"])
@_requires_auth
def object_put(bucket, key, identity):
    args = request.args

    if "partNumber" in args and "uploadId" in args:
        upload = s3_db.get_multipart_upload(args["uploadId"])
        if not upload:
            return _error("NoSuchUpload", "The specified multipart upload does not exist.", 404, bucket=bucket, key=key)
        data = s3_auth.resolve_body(request)
        storage_path, etag, size = s3_storage.write_part(args["uploadId"], int(args["partNumber"]), data)
        s3_db.add_part(args["uploadId"], int(args["partNumber"]), etag, size, storage_path)
        return Response(status=200, headers={"ETag": f'"{etag}"'})

    if "tagging" in args:
        tags = _tagging_to_dict(request.get_data())
        obj = s3_db.get_object(bucket, key)
        if not obj:
            return _no_such_key(bucket, key)
        s3_db.set_object_tags(bucket, key, None, tags)
        return _xml("", status=200)

    bucket_row = s3_db.get_bucket(bucket)
    if not bucket_row:
        return _no_such_bucket(bucket)

    copy_source = request.headers.get("x-amz-copy-source")
    if copy_source:
        src = unquote(copy_source.lstrip("/"))
        src_bucket, _, rest = src.partition("/")
        src_key, _, version_qs = rest.partition("?versionId=")
        src_version = version_qs or None
        src_obj = s3_db.get_object(src_bucket, src_key, version_id=src_version)
        if not src_obj:
            return _no_such_key(src_bucket, src_key)
        data = s3_storage.read_object(src_obj["storage_path"])
        versioned = bucket_row["versioning_status"] == "Enabled"
        storage_path, etag, size = s3_storage.write_object(bucket, key, data)
        new_obj = s3_db.put_object(bucket, key, size, etag, src_obj["content_type"], storage_path, tags=src_obj["tags"], versioned=versioned)
        return _xml(f'<CopyObjectResult><ETag>"{new_obj["etag"]}"</ETag><LastModified>{new_obj["last_modified"]}</LastModified></CopyObjectResult>')

    data = s3_auth.resolve_body(request)
    content_type = request.headers.get("Content-Type", "application/octet-stream")
    versioned = bucket_row["versioning_status"] == "Enabled"
    tags = _parse_tagging_header(request.headers.get("x-amz-tagging"))
    storage_path, etag, size = s3_storage.write_object(bucket, key, data)
    obj = s3_db.put_object(bucket, key, size, etag, content_type, storage_path, tags=tags, versioned=versioned)
    headers = {"ETag": f'"{obj["etag"]}"'}
    if obj["version_id"] != "null":
        headers["x-amz-version-id"] = obj["version_id"]
    return Response(status=200, headers=headers)


@bp.route("/<bucket>/<path:key>", methods=["GET"])
@_requires_auth
def object_get(bucket, key, identity):
    args = request.args

    if "uploadId" in args and "partNumber" not in args:
        parts = s3_db.list_parts(args["uploadId"])
        items = "".join(f'<Part><PartNumber>{p["part_number"]}</PartNumber><ETag>"{p["etag"]}"</ETag><Size>{p["size"]}</Size></Part>' for p in parts)
        return _xml(f'<ListPartsResult xmlns="{NS}"><Bucket>{bucket}</Bucket><Key>{key}</Key>{items}</ListPartsResult>')

    if "tagging" in args:
        obj = s3_db.get_object(bucket, key, version_id=args.get("versionId"))
        if not obj:
            return _no_such_key(bucket, key)
        return _xml(_tags_to_xml(obj["tags"]))

    obj = s3_db.get_object(bucket, key, version_id=args.get("versionId"))
    if not obj or obj["is_delete_marker"]:
        return _no_such_key(bucket, key)
    data = s3_storage.read_object(obj["storage_path"])
    headers = {
        "ETag": f'"{obj["etag"]}"',
        "Content-Type": obj["content_type"] or "application/octet-stream",
        "Last-Modified": _http_date(obj["last_modified"]),
    }
    if obj["version_id"] != "null":
        headers["x-amz-version-id"] = obj["version_id"]
    return Response(data, status=200, headers=headers)


@bp.route("/<bucket>/<path:key>", methods=["HEAD"])
@_requires_auth
def object_head(bucket, key, identity):
    obj = s3_db.get_object(bucket, key, version_id=request.args.get("versionId"))
    if not obj or obj["is_delete_marker"]:
        return Response(status=404)
    headers = {
        "ETag": f'"{obj["etag"]}"',
        "Content-Type": obj["content_type"] or "application/octet-stream",
        "Content-Length": str(obj["size"]),
        "Last-Modified": _http_date(obj["last_modified"]),
    }
    if obj["version_id"] != "null":
        headers["x-amz-version-id"] = obj["version_id"]
    return Response(status=200, headers=headers)


@bp.route("/<bucket>/<path:key>", methods=["DELETE"])
@_requires_auth
def object_delete(bucket, key, identity):
    args = request.args

    if "uploadId" in args:
        upload = s3_db.get_multipart_upload(args["uploadId"])
        if upload:
            s3_storage.delete_multipart_temp(args["uploadId"])
            s3_db.abort_multipart_upload(args["uploadId"])
        return Response(status=204)

    if "tagging" in args:
        s3_db.set_object_tags(bucket, key, args.get("versionId"), {})
        return Response(status=204)

    if not s3_db.get_bucket(bucket):
        return _no_such_bucket(bucket)

    _delete_one(bucket, key, args.get("versionId"))
    headers = {}
    if args.get("versionId"):
        headers["x-amz-version-id"] = args["versionId"]
    return Response(status=204, headers=headers)


@bp.route("/<bucket>/<path:key>", methods=["POST"])
@_requires_auth
def object_post(bucket, key, identity):
    args = request.args

    if "uploads" in args:
        content_type = request.headers.get("Content-Type", "application/octet-stream")
        upload_id = s3_db.create_multipart_upload(bucket, key, content_type)
        return _xml(f'<InitiateMultipartUploadResult xmlns="{NS}"><Bucket>{bucket}</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>')

    if "uploadId" in args:
        upload_id = args["uploadId"]
        upload = s3_db.get_multipart_upload(upload_id)
        if not upload:
            return _error("NoSuchUpload", "The specified multipart upload does not exist.", 404, bucket=bucket, key=key)

        root = ET.fromstring(request.get_data()) if request.get_data() else None
        requested_parts = None
        if root is not None:
            requested_parts = [int(_find_local(p, "PartNumber").text) for p in _findall_local(root, "Part")]

        parts = s3_db.list_parts(upload_id)
        if requested_parts:
            parts = sorted([p for p in parts if p["part_number"] in requested_parts], key=lambda p: p["part_number"])

        bucket_row = s3_db.get_bucket(bucket)
        versioned = bool(bucket_row and bucket_row["versioning_status"] == "Enabled")
        storage_path, _content_etag, size = s3_storage.concatenate_parts(bucket, key, [p["storage_path"] for p in parts])
        final_etag = s3_storage.multipart_etag([p["etag"] for p in parts])
        obj = s3_db.put_object(bucket, key, size, final_etag, upload.get("content_type") or "application/octet-stream", storage_path, versioned=versioned)

        s3_storage.delete_multipart_temp(upload_id)
        s3_db.complete_multipart_upload(upload_id)

        return _xml(f'<CompleteMultipartUploadResult xmlns="{NS}"><Location>/{bucket}/{key}</Location><Bucket>{bucket}</Bucket><Key>{key}</Key><ETag>"{obj["etag"]}"</ETag></CompleteMultipartUploadResult>')

    return _error("NotImplemented", "Unsupported object POST operation.", 501, bucket=bucket, key=key)
