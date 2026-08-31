"""IAM + STS query-protocol action handlers (mode: ec2, all).

Real identity/credential management when DATABASE_URL is configured;
otherwise falls back to the single hardcoded 'emulator' identity the
emulator has always exposed, so the zero-config quickstart keeps working
with no Postgres dependency.
"""
import psycopg2.errors
from flask import Response

import db
import iam_db
from core import XML

IAM_NS = "https://iam.amazonaws.com/doc/2010-05-08/"
STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"

_FALLBACK_USER = {
    "user_name": iam_db.DEFAULT_SEED_USER,
    "user_id": "AIDACKCEVSQ6C2EXAMPLE",
    "arn": iam_db.user_arn(iam_db.DEFAULT_SEED_USER),
    "path": "/",
    "create_date": "2024-01-01T00:00:00.000Z",
}


def _query(action, content, namespace=IAM_NS):
    return Response(XML.wrap_query(action, content, namespace=namespace), mimetype="text/xml")


def _error(action, code, message, status=400, namespace=IAM_NS):
    body, status = XML.error_query(code, message, status=status, namespace=namespace)
    return Response(body, status=status, mimetype="text/xml")


def _user_xml(u):
    return f"<Path>{u['path']}</Path><UserName>{u['user_name']}</UserName><UserId>{u['user_id']}</UserId><Arn>{u['arn']}</Arn><CreateDate>{u['create_date']}</CreateDate>"


def _key_meta_xml(k, include_secret):
    secret = f"<SecretAccessKey>{k['secret_access_key']}</SecretAccessKey>" if include_secret else ""
    return f"<UserName>{k['user_name']}</UserName><AccessKeyId>{k['access_key_id']}</AccessKeyId><Status>{k['status']}</Status>{secret}<CreateDate>{k['create_date']}</CreateDate>"


def resolve_caller_identity(request):
    """Best-effort identity for GetCallerIdentity: looks at the Authorization
    header's access key if IAM is DB-backed, else the fixed fallback identity.
    Not a security check - just informational (EC2/IAM endpoints aren't
    SigV4-enforced; only S3 enforces auth, see s3_auth.py).
    """
    if db.is_configured():
        auth = request.headers.get("Authorization", "")
        if "Credential=" in auth:
            cred = auth.split("Credential=", 1)[1].split(",", 1)[0].strip()
            access_key_id = cred.split("/")[0]
            row = iam_db.get_credential(access_key_id)
            if row:
                user_name, _secret, _status = row
                user = iam_db.get_user(user_name)
                if user:
                    return user
        try:
            users = iam_db.list_users()
            if users:
                return users[0]
        except Exception:
            pass
    return _FALLBACK_USER


def dispatch(action, req, request=None):
    use_db = db.is_configured()

    if action == "GetCallerIdentity":
        identity = resolve_caller_identity(request) if request is not None else _FALLBACK_USER
        content = f"<Arn>{identity['arn']}</Arn><UserId>{identity['user_id']}</UserId><Account>{iam_db.account_id()}</Account>"
        return _query(action, content, namespace=STS_NS)

    if action == "GetUser":
        identity = resolve_caller_identity(request) if request is not None else _FALLBACK_USER
        requested = req.get("UserName")
        user = iam_db.get_user(requested) if (use_db and requested) else identity
        if requested and use_db and not user:
            return _error(action, "NoSuchEntity", f"The user with name {requested} cannot be found.", status=404)
        return _query(action, f"<User>{_user_xml(user)}</User>")

    if action == "ListRoles":
        return _query(action, "<Roles/><IsTruncated>false</IsTruncated>")

    # No groups/roles/policies support (see module docstring) - but these
    # read-only lookups still need to succeed-with-nothing, not error, since
    # the provider calls them as part of unwinding a user before deleting it
    # (an unhandled error here aborts the whole `terraform destroy`).
    if action == "ListGroupsForUser":
        return _query(action, "<Groups/><IsTruncated>false</IsTruncated>")
    if action == "ListAttachedUserPolicies":
        return _query(action, "<AttachedPolicies/><IsTruncated>false</IsTruncated>")
    if action == "ListUserPolicies":
        return _query(action, "<PolicyNames/><IsTruncated>false</IsTruncated>")
    if action == "ListMFADevices":
        return _query(action, "<MFADevices/><IsTruncated>false</IsTruncated>")
    if action == "ListSigningCertificates":
        return _query(action, "<Certificates/><IsTruncated>false</IsTruncated>")
    if action == "ListServiceSpecificCredentials":
        return _query(action, "<ServiceSpecificCredentials/>")
    if action == "ListSSHPublicKeys":
        return _query(action, "<SSHPublicKeys/><IsTruncated>false</IsTruncated>")

    if not use_db:
        # IAM management actions genuinely need Postgres; everything else
        # (GetCallerIdentity/GetUser/ListRoles) already works via fallback above.
        if action in ("CreateUser", "GetUser", "ListUsers", "DeleteUser", "CreateAccessKey", "ListAccessKeys", "DeleteAccessKey", "UpdateAccessKey", "GetAccessKeyLastUsed"):
            return _error(action, "InternalFailure", "IAM user/key management requires DATABASE_URL to be configured.", status=500)
        return None

    if action == "CreateUser":
        user_name = req.get("UserName")
        try:
            user = iam_db.create_user(user_name, req.get("Path", "/"))
        except psycopg2.errors.UniqueViolation:
            return _error(action, "EntityAlreadyExists", f"User with name {user_name} already exists.", status=409)
        return _query(action, f"<User>{_user_xml(user)}</User>")

    if action == "ListUsers":
        members = "".join([f"<member>{_user_xml(u)}</member>" for u in iam_db.list_users()])
        return _query(action, f"<Users>{members}</Users><IsTruncated>false</IsTruncated>")

    if action == "DeleteUser":
        iam_db.delete_user(req.get("UserName"))
        return _query(action, "")

    if action == "CreateAccessKey":
        user_name = req.get("UserName") or (resolve_caller_identity(request)["user_name"] if request is not None else iam_db.DEFAULT_SEED_USER)
        key = iam_db.create_access_key(user_name)
        return _query(action, f"<AccessKey>{_key_meta_xml(key, include_secret=True)}</AccessKey>")

    if action == "ListAccessKeys":
        user_name = req.get("UserName") or (resolve_caller_identity(request)["user_name"] if request is not None else iam_db.DEFAULT_SEED_USER)
        members = "".join([f"<member>{_key_meta_xml(k, include_secret=False)}</member>" for k in iam_db.list_access_keys(user_name)])
        return _query(action, f"<AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated>")

    if action == "DeleteAccessKey":
        iam_db.delete_access_key(req.get("AccessKeyId"), req.get("UserName"))
        return _query(action, "")

    if action == "UpdateAccessKey":
        iam_db.update_access_key(req.get("AccessKeyId"), req.get("Status"))
        return _query(action, "")

    if action == "GetAccessKeyLastUsed":
        akid = req.get("AccessKeyId")
        row = iam_db.get_credential(akid) if akid else None
        user_name = row[0] if row else ""
        return _query(action, f"<UserName>{user_name}</UserName><AccessKeyLastUsed><LastUsedDate>2024-01-01T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed>")

    return None
