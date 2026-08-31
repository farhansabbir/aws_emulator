# Lightweight AWS Emulator

A small, self-hosted emulator for **EC2/VPC**, **S3**, and **IAM** that speaks the real AWS wire protocols (EC2 query/XML, S3 REST/XML, IAM query/XML) closely enough for `terraform apply`, the `aws` CLI, and the AWS SDKs to work against it unmodified. No AWS account, no cost, fully local or containerized.

* **EC2/VPC**: instances, VPCs, subnets, security groups (ingress + egress, real rule IDs), internet/NAT gateways, Elastic IPs, tags. In-memory, single process — this is a Terraform-testing convenience, not a service meant to run at scale.
* **IAM**: users and long-term access keys, Postgres-backed. Identity/credential management only — no groups, roles, policy documents, or authorization evaluation.
* **S3**: buckets and objects — CRUD, listing, multipart upload, tagging, versioning, and common bucket sub-resource configs — authenticated with **real SigV4 signature verification** against IAM-issued credentials. Postgres for metadata, a shared volume for object bytes, so it can run as many replicas behind a load balancer.

The image runs as a non-root user with a read-only root filesystem, and both `docker-compose.yml` and the `k8s/` manifests drop all Linux capabilities (adding back only the handful Postgres's own entrypoint genuinely needs), set `allowPrivilegeEscalation: false`/`no-new-privileges`, and define CPU/memory requests and limits on every container.

## Architecture

One codebase, one Docker image, three run modes via `SERVICE_MODE`:

| Mode | Serves | State | Scaling |
|---|---|---|---|
| `ec2` | EC2, VPC, IAM (management), STS | EC2/VPC in-memory; IAM in Postgres | Single replica |
| `s3` | S3 REST API only | Postgres (metadata) + shared volume (object bytes); reads IAM from Postgres to verify SigV4 | Many replicas |
| `all` (default) | Everything, one process | Same as above, combined | Single replica — the zero-config quickstart |

Why EC2/VPC don't scale out: their state is in-process memory. A `DescribeVpcs` on replica B wouldn't see a `CreateVpc` that hit replica A, which is strictly worse for Terraform testing. S3 is the part actually built to run as multiple replicas — it's stateless per-process, backed entirely by Postgres + a shared volume.

Everything listens on one port (`4566` by default) and is routed by protocol, not by service-specific ports — this mirrors how the example Terraform provider block below points `ec2`/`iam`/`sts` and `s3` at the same host:port pair. `POST /` with a form field `Action` is EC2/IAM/STS query-protocol; everything else (`GET/PUT/DELETE/HEAD` on `/`, `/<bucket>`, `/<bucket>/<key>`) is S3 REST. S3 addressing is **path-style only** (`http://host:4566/bucket/key`) — no virtual-hosted-style (`bucket.host:4566/key`), which is why the example provider config below sets `s3_use_path_style = true`.

**Backward compatibility**: if `DATABASE_URL` isn't set, `ec2`/`all` mode still runs exactly like the original version of this project — a single hardcoded `emulator`/`123456789012` identity, no real IAM user/key management, EC2/VPC fully functional. Postgres is only required once you want real IAM users/keys or any S3 usage.

## Quickstart

### 1. Plain Python (no Docker) — EC2/VPC only, zero dependencies beyond Flask

```bash
cd aws_emulator
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

This runs in `all` mode by default, but with no `DATABASE_URL` set, IAM management and S3 are disabled (EC2/VPC work fully with the fixed `test`/`test` credentials). To get real IAM + S3 here too, export `DATABASE_URL` before running (see [Environment variables](#environment-variables)).

### 2. Docker — everything in one container

```bash
docker build -t aws_emulator .
docker run -p 4566:4566 \
  -e DATABASE_URL=postgresql://user:pass@your-postgres-host:5432/aws_emulator \
  -v s3-data:/data/objects \
  aws_emulator
```

Omit `DATABASE_URL` for EC2/VPC-only use (same fallback as above).

### 3. Docker Compose — the multi-service, scaled-S3 demo

```bash
docker compose up -d --build
docker compose up -d --scale s3=3   # scale the S3 service out
```

This brings up: `db` (Postgres), `ec2-vpc` (single replica, published on `:4566`), `s3` (as many replicas as you scale to, no host port of its own), and `s3-lb` (nginx, published on `:4567`, round-robins across every `s3` replica using Docker's embedded DNS). Point Terraform's `ec2`/`iam`/`sts` endpoints at `:4566` and its `s3` endpoint at `:4567`.

### 4. Kubernetes — the same topology, cluster-native

```bash
kubectl apply -f k8s/
```

Creates the `aws-emulator` namespace with a single-replica `postgres` Deployment+PVC, a single-replica `ec2-vpc` Deployment+Service, and a 3-replica `s3` Deployment+Service backed by a **ReadWriteMany** PVC (every `s3` pod mounts the same object-data volume — see the comments in `k8s/04-s3.yaml` for picking an RWX-capable StorageClass, e.g. NFS or the EFS CSI driver; single-node dev clusters can drop to `replicas: 1` + `ReadWriteOnce` instead). Update the image reference in `k8s/03-ec2-vpc.yaml`/`k8s/04-s3.yaml` if you're not using the published `ghcr.io/farhansabbir/aws_emulator` image.

## Endpoint map

| Deployment | EC2 / VPC / IAM / STS | S3 |
|---|---|---|
| Plain Python / `docker run` (`SERVICE_MODE=all`) | `http://localhost:4566` | `http://localhost:4566` |
| Docker Compose | `http://localhost:4566` | `http://localhost:4567` (via `s3-lb`) |
| Kubernetes | `http://ec2-vpc.aws-emulator.svc.cluster.local:4566` (or however you expose the `ec2-vpc` Service) | `http://s3.aws-emulator.svc.cluster.local:4566` (or however you expose the `s3` Service) |

## Default credentials

A seed IAM user is created automatically the first time IAM's schema initializes (only if no users exist yet): `user_name=emulator`, `access_key_id=test`, `secret_access_key=test` — so any existing Terraform config using `access_key = "test"` / `secret_key = "test"` keeps working unchanged. Create additional users/keys with the normal `aws_iam_user`/`aws_iam_access_key` Terraform resources or `aws iam create-user`/`create-access-key`.

## Usage

The commands below use the `aws` CLI directly against the zero-config single-process endpoint (`http://localhost:4566`, `SERVICE_MODE=all`, default `test`/`test` credentials) — the fastest way to poke at any of the three services without writing Terraform. Every command here doubles as something this project's own automated verification actually ran against the emulator. Swap in your own endpoint/credentials for Compose (`:4566` for EC2/IAM, `:4567` for S3) or Kubernetes.

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
EP=http://localhost:4566
```

### EC2 / VPC

```bash
# Network: a VPC, a subnet, a security group with an ingress rule
VPC_ID=$(aws --endpoint-url $EP ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)
SUBNET_ID=$(aws --endpoint-url $EP ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.0.10.0/24 \
  --availability-zone us-east-1a --query 'Subnet.SubnetId' --output text)
SG_ID=$(aws --endpoint-url $EP ec2 create-security-group --group-name web --description "web sg" \
  --vpc-id "$VPC_ID" --query 'GroupId' --output text)
aws --endpoint-url $EP ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 --cidr 0.0.0.0/0

# Compute: launch, inspect, tear down
INSTANCE_ID=$(aws --endpoint-url $EP ec2 run-instances --image-id ami-12345678 --instance-type t2.micro \
  --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" --count 1 --query 'Instances[0].InstanceId' --output text)
aws --endpoint-url $EP ec2 describe-instances --instance-ids "$INSTANCE_ID"
aws --endpoint-url $EP ec2 terminate-instances --instance-ids "$INSTANCE_ID"
```

Or drive the same thing with Terraform — see `provider.tf`/`outputs.tf` for the fuller worked example (VPC, subnets, an internet gateway, the security group above, the instance, a NAT gateway + Elastic IP).

### IAM

```bash
# Create a user and a real access key for it (distinct from the seeded test/test key)
aws --endpoint-url $EP iam create-user --user-name alice
AK_JSON=$(aws --endpoint-url $EP iam create-access-key --user-name alice)
ALICE_KEY=$(echo "$AK_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")
ALICE_SECRET=$(echo "$AK_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKey']['SecretAccessKey'])")

# Prove it's a real, distinct identity - GetCallerIdentity reflects whoever actually signed the request
AWS_ACCESS_KEY_ID=$ALICE_KEY AWS_SECRET_ACCESS_KEY=$ALICE_SECRET \
  aws --endpoint-url $EP sts get-caller-identity

aws --endpoint-url $EP iam list-users
aws --endpoint-url $EP iam list-access-keys --user-name alice   # note: no SecretAccessKey here - only at creation, same as real IAM
aws --endpoint-url $EP iam delete-access-key --user-name alice --access-key-id "$ALICE_KEY"
aws --endpoint-url $EP iam delete-user --user-name alice
```

`alice`'s new key isn't just decorative — it's a real credential you can hand to the S3 walkthrough below instead of the seeded `test`/`test` one, since S3 actually verifies whichever access key/secret pair signed the request against whatever IAM knows about (this is the whole point of IAM existing in this emulator: to back S3's SigV4 checks with real, independently-manageable credentials, not to be a policy engine — see [What's implemented](#iam) for the scope boundary).

### S3

```bash
# Buckets and a plain object
aws --endpoint-url $EP s3 mb s3://my-bucket
echo "hello" | aws --endpoint-url $EP s3 cp - s3://my-bucket/hello.txt
aws --endpoint-url $EP s3 ls s3://my-bucket/
aws --endpoint-url $EP s3 cp s3://my-bucket/hello.txt -

# Versioning + tagging
aws --endpoint-url $EP s3api put-bucket-versioning --bucket my-bucket --versioning-configuration Status=Enabled
echo "v2" | aws --endpoint-url $EP s3 cp - s3://my-bucket/hello.txt   # now creates a new version, not an overwrite
aws --endpoint-url $EP s3api list-object-versions --bucket my-bucket --prefix hello.txt
aws --endpoint-url $EP s3api put-object-tagging --bucket my-bucket --key hello.txt \
  --tagging 'TagSet=[{Key=env,Value=demo}]'

# Multipart upload (same API real large-object uploads use under the hood)
UPLOAD_ID=$(aws --endpoint-url $EP s3api create-multipart-upload --bucket my-bucket --key big.bin --query UploadId --output text)
ETAG1=$(aws --endpoint-url $EP s3api upload-part --bucket my-bucket --key big.bin --part-number 1 \
  --upload-id "$UPLOAD_ID" --body part1.bin --query ETag --output text)
aws --endpoint-url $EP s3api complete-multipart-upload --bucket my-bucket --key big.bin --upload-id "$UPLOAD_ID" \
  --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":$ETAG1}]}"

# Clean up - force_destroy-style bulk delete, then the (now-empty) bucket
aws --endpoint-url $EP s3api delete-objects --bucket my-bucket \
  --delete '{"Objects":[{"Key":"hello.txt"},{"Key":"big.bin"}]}'
aws --endpoint-url $EP s3api delete-bucket --bucket my-bucket
```

Every one of these requests is SigV4-authenticated against IAM (unless `S3_AUTH_MODE=off`) — swap `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` for the `alice` credentials from the IAM walkthrough above and it behaves identically, since the emulator doesn't special-case the seeded user. A signature computed with the wrong secret, or an access key IAM doesn't know about, gets a real `SignatureDoesNotMatch`/`InvalidAccessKeyId` rejection, not a silent pass-through.

## Example Terraform provider block

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # see "Terraform provider version" below
    }
  }
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true

  endpoints {
    ec2 = "http://localhost:4566"
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
    s3  = "http://localhost:4566"   # or :4567 behind Docker Compose's s3-lb
  }
}
```

See `provider.tf`/`outputs.tf` in this repo for a fuller worked example (VPC, subnets, security groups, an instance, NAT/EIP, an S3 bucket + object, an IAM user + access key) — verified end-to-end (`init` / `apply` / `plan` showing zero drift / `destroy`) against a real `terraform-provider-aws`.

### Terraform provider version

Pin `hashicorp/aws` to `~> 5.0`. Provider v6's `aws_s3_bucket` resource unconditionally calls S3 Control's `ListTagsForResource` on every create/read — a separate JSON REST protocol this emulator doesn't implement, and with no `s3control` endpoint override that call goes to real AWS and is rejected (`403 AccessDenied`), failing every `aws_s3_bucket`. v5.x's S3 bucket resource doesn't make that call. `aws_iam_user`/`aws_iam_access_key`/EC2·VPC resources aren't affected either way.

If a bucket has versioning enabled, deleting an `aws_s3_object` only adds a delete marker (real S3 behavior) — the bucket still "contains" object versions, so a plain `terraform destroy` will fail with `BucketNotEmpty` on the bucket unless it has `force_destroy = true` (see `provider.tf`'s `aws_s3_bucket.artifacts` for an example), same as real AWS.

## What's implemented (and what isn't)

### EC2 / VPC

Instances (run/describe/start/stop/terminate, attribute get/modify), VPCs (with `cidrBlockAssociationSet`), subnets, security groups (ingress **and** egress, real `sgr-*` rule IDs, `DescribeSecurityGroupRules`), internet gateways, NAT gateways, Elastic IPs, tags. Not implemented: launch templates (stubbed success only), most `Describe*` filters beyond `vpc-id`/`subnet-id`/`group-id`/`instance-id`/etc., IPv6, VPC peering, Transit Gateway, Auto Scaling.

### IAM

Users and long-term access keys (create/list/delete/update-status), `GetCallerIdentity`/`GetUser` reflecting the actual signed-in caller. **Not implemented**: groups, roles, policy documents, or any authorization evaluation — this exists to back S3's SigV4 verification with real credentials, not to be a policy engine. Every EC2/VPC and IAM-management request is currently unauthenticated (matches the original project's behavior); only **S3** enforces signatures.

### S3

Buckets: create/delete/head/list, location, tagging, versioning, ACL/policy/CORS/encryption/public-access-block (stored and returned, **not enforced** — see below), `ListObjects`/`ListObjectsV2`, bulk delete. Objects: put/get/head/delete (incl. `?versionId=`), copy, tagging, multipart upload (create/upload-part/complete/abort/list-parts). Delete creates a delete marker when versioning is enabled.

**Explicitly not implemented**: replication; lifecycle rule *execution* (config is stored/returned, nothing actually transitions or expires); object lock/retention/legal hold; requester-pays enforcement; real ACL/policy *authorization* (every request is already gated by SigV4 identity — there's no separate per-object authorization layer on top); event notifications; inventory/analytics configs; presigned-URL (query-string) auth (header-based SigV4, what the AWS provider and CLI use by default, is fully supported); virtual-hosted-style addressing; at-rest encryption of bytes; S3 Select; Access Points/Object Lambda.

**SigV4 note**: the top-level request signature is fully verified against IAM-issued credentials. For chunked/streaming uploads (`x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), the chunk framing is decoded to recover the real object bytes, but individual chunk signatures aren't each independently re-verified.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `SERVICE_MODE` | `all` | `all`, `ec2`, or `s3` — see [Architecture](#architecture) |
| `PORT` | `4566` | Port the app listens on |
| `DATABASE_URL` | *(unset)* | Postgres DSN, e.g. `postgresql://user:pass@host:5432/db`. Required for IAM management and for any S3 usage; EC2/VPC work without it |
| `S3_DATA_DIR` | `/data/objects` | Where S3 object bytes are stored (mount a shared volume here across replicas) |
| `S3_AUTH_MODE` | `enforce` | `enforce` (real SigV4 verification) or `off` (skip auth entirely, for zero-friction local testing) |
| `EMULATOR_ACCOUNT_ID` | `123456789012` | The fake AWS account ID used throughout ARNs and responses |

## Known limitations across the board

This is a testing/development tool, not a production AWS replacement: no rate limiting, no real billing/cost simulation, no CloudTrail/audit logging, minimal input validation (malformed requests may behave unpredictably rather than returning precise AWS error codes), and the feature scope above is deliberately bounded to what `terraform-provider-aws`, the `aws` CLI, and typical SDK usage actually exercise.
