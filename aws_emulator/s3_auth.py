"""AWS Signature Version 4 verification for S3 requests.

Verifies the top-level request signature against IAM-issued credentials
(iam_db). Presigned-URL (query-string) auth is not supported - documented
limitation; this only handles header-based signing (Authorization header),
which is what the AWS provider/CLI/SDKs use by default.

Also decodes the `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` chunked-upload wire
format to recover real object bytes for storage. The top-level request
signature is fully verified; individual chunk signatures within a
streamed upload are decoded but not each independently re-verified.
"""
import hashlib
import hmac
import os
from urllib.parse import quote, parse_qsl

import iam_db

UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
STREAMING_PAYLOAD = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
STREAMING_PAYLOAD_TRAILER = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"


class AuthError(Exception):
    def __init__(self, code, message, status=403):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


def auth_enabled():
    return os.environ.get("S3_AUTH_MODE", "enforce").lower() != "off"


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret, date_stamp, region, service):
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _canonical_uri(path):
    if not path:
        return "/"
    segments = path.split("/")
    return "/".join(quote(seg, safe="-_.~") for seg in segments)


def _canonical_query_string(query_string):
    pairs = parse_qsl(query_string, keep_blank_values=True)
    encoded = sorted(
        (quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in pairs
    )
    return "&".join(f"{k}={v}" for k, v in encoded)


def _trim(value):
    return " ".join(value.split())


def _parse_authorization(auth_header):
    if not auth_header or not auth_header.startswith("AWS4-HMAC-SHA256 "):
        raise AuthError("AccessDenied", "Missing or unsupported Authorization header.", 403)
    parts = auth_header[len("AWS4-HMAC-SHA256 "):].split(",")
    fields = {}
    for part in parts:
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        fields[k.strip()] = v.strip()
    credential = fields.get("Credential")
    signed_headers = fields.get("SignedHeaders")
    signature = fields.get("Signature")
    if not credential or not signed_headers or not signature:
        raise AuthError("AccessDenied", "Malformed Authorization header.", 403)
    try:
        access_key_id, date_stamp, region, service, terminator = credential.split("/")
    except ValueError:
        raise AuthError("AccessDenied", "Malformed credential scope.", 403)
    return {
        "access_key_id": access_key_id,
        "date_stamp": date_stamp,
        "region": region,
        "service": service,
        "signed_headers": signed_headers.split(";"),
        "signature": signature,
    }


def decode_aws_chunked_body(raw):
    """Strips AWS chunked-upload framing, returning the real payload bytes."""
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        line_end = raw.find(b"\r\n", i)
        if line_end == -1:
            break
        header = raw[i:line_end]
        size_hex = header.split(b";", 1)[0]
        try:
            size = int(size_hex, 16)
        except ValueError:
            break
        chunk_start = line_end + 2
        chunk_end = chunk_start + size
        out.extend(raw[chunk_start:chunk_end])
        i = chunk_end + 2  # skip trailing \r\n after the chunk data
        if size == 0:
            break
    return bytes(out)


def verify(request):
    """Verifies `request` (a Flask request), raising AuthError on failure.
    Returns (access_key_id, user_name) on success."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        if "X-Amz-Signature" in request.args or "X-Amz-Credential" in request.args:
            raise AuthError(
                "NotImplemented",
                "Presigned URL (query-string) authentication is not supported by this emulator; use header-based SigV4 signing.",
                501,
            )
        raise AuthError("AccessDenied", "Anonymous requests are not supported.", 403)

    parsed = _parse_authorization(auth_header)
    access_key_id = parsed["access_key_id"]

    credential = iam_db.get_credential(access_key_id)
    if not credential:
        raise AuthError("InvalidAccessKeyId", f"The AWS access key '{access_key_id}' does not exist.", 403)
    user_name, secret, status = credential
    if status != "Active":
        raise AuthError("InvalidAccessKeyId", f"The access key '{access_key_id}' is not active.", 403)

    amz_date = request.headers.get("X-Amz-Date") or request.headers.get("x-amz-date")
    if not amz_date:
        raise AuthError("AccessDenied", "Missing X-Amz-Date header.", 403)

    # Real S3 clients (boto3/aws-cli) always send this header. Fall back to
    # hashing the actual received body ourselves, matching the generic
    # SigV4 default, for any client that omits it.
    payload_hash_header = request.headers.get("X-Amz-Content-Sha256")
    if not payload_hash_header:
        payload_hash_header = hashlib.sha256(request.get_data()).hexdigest()

    headers_lookup = {h.lower(): request.headers.get(h, "") for h in parsed["signed_headers"]}
    canonical_headers = "".join(f"{h}:{_trim(headers_lookup[h])}\n" for h in parsed["signed_headers"])
    signed_headers_str = ";".join(parsed["signed_headers"])

    canonical_request = "\n".join([
        request.method,
        _canonical_uri(request.path),
        _canonical_query_string(request.query_string.decode("utf-8")),
        canonical_headers,
        signed_headers_str,
        payload_hash_header,
    ])
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

    credential_scope = f"{parsed['date_stamp']}/{parsed['region']}/{parsed['service']}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashed_canonical_request,
    ])

    signing_key = _signing_key(secret, parsed["date_stamp"], parsed["region"], parsed["service"])
    expected_signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, parsed["signature"]):
        raise AuthError("SignatureDoesNotMatch", "The request signature does not match the one computed by the server.", 403)

    return access_key_id, user_name


def resolve_body(request):
    """Returns the real payload bytes, decoding AWS chunked-upload framing
    if present. Safe to call regardless of auth mode."""
    raw = request.get_data()
    content_sha = request.headers.get("X-Amz-Content-Sha256", "")
    if content_sha in (STREAMING_PAYLOAD, STREAMING_PAYLOAD_TRAILER):
        return decode_aws_chunked_body(raw)
    return raw


def resolve_identity_unchecked(request):
    """Best-effort identity when S3_AUTH_MODE=off - no signature check."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("AWS4-HMAC-SHA256 "):
        try:
            parsed = _parse_authorization(auth_header)
            credential = iam_db.get_credential(parsed["access_key_id"])
            if credential:
                return parsed["access_key_id"], credential[0]
        except AuthError:
            pass
    return iam_db.DEFAULT_SEED_ACCESS_KEY, iam_db.DEFAULT_SEED_USER
