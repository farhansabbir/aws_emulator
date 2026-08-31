terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # AWS provider v6's aws_s3_bucket resource unconditionally calls
      # S3 Control's ListTagsForResource as part of every create/read -
      # a different (JSON REST) protocol this emulator doesn't implement,
      # and since there's no s3control endpoint override, that call goes
      # to real AWS and gets rejected. v5.x's S3 bucket resource doesn't
      # do this. Pinned here so `aws_s3_bucket` keeps working out of the box.
      version = "~> 5.0"
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
    apigateway     = "http://localhost:4566"
    apigatewayv2   = "http://localhost:4566"
    cloudformation = "http://localhost:4566"
    cloudwatch     = "http://localhost:4566"
    dynamodb       = "http://localhost:4566"
    ec2            = "http://localhost:4566"
    es             = "http://localhost:4566"
    elasticache    = "http://localhost:4566"
    firehose       = "http://localhost:4566"
    iam            = "http://localhost:4566"
    kinesis        = "http://localhost:4566"
    lambda         = "http://localhost:4566"
    rds            = "http://localhost:4566"
    redshift       = "http://localhost:4566"
    route53        = "http://localhost:4566"
    s3             = "http://localhost:4566" # ":4567" if you're using docker-compose's s3-lb
    secretsmanager = "http://localhost:4566"
    ses            = "http://localhost:4566"
    sns            = "http://localhost:4566"
    sqs            = "http://localhost:4566"
    ssm            = "http://localhost:4566"
    stepfunctions  = "http://localhost:4566"
    sts            = "http://localhost:4566"
    # vpc            = "http://localhost:4566"
  }
}

resource "aws_vpc" "default_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "default_subnet" {
  vpc_id     = aws_vpc.default_vpc.id
  cidr_block = "10.0.10.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private_subnet" {
  vpc_id     = aws_vpc.default_vpc.id
  cidr_block = "10.0.100.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = false
}

resource "aws_internet_gateway" "default_igw" {
    vpc_id = aws_vpc.default_vpc.id
}

resource "aws_security_group" "web" {
    vpc_id = aws_vpc.default_vpc.id
}

resource "aws_security_group_rule" "web_allow_http_from_any" {
  type = "ingress"

  protocol = "tcp"
  from_port = 80
  to_port = 80
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = "${aws_security_group.web.id}"
}

resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.default_subnet.id
  
  # Link to the security group we made earlier
  vpc_security_group_ids = [aws_security_group.web.id]



  tags = {
    Name = "Emulator-Instance"
  }
}

output "instance_ip" {
  value = aws_instance.app_server.private_ip
}
data "aws_caller_identity" "current" {}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "example" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.default_subnet.id
}

# The IP you use for whitelisting
output "outbound_ip_address" {
  value = aws_eip.nat.public_ip
}

# --- IAM + S3 ---
# A dedicated app identity (rather than reusing the seeded "test"/"test"
# credentials) whose key S3 actually SigV4-authenticates against.
resource "aws_iam_user" "app" {
  name = "emulator-demo-app"
}

resource "aws_iam_access_key" "app" {
  user = aws_iam_user.app.name
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "emulator-demo-artifacts"
  # Versioning means "delete the object" only adds a delete marker (real S3
  # behavior) - force_destroy makes `terraform destroy` clean up every
  # version and delete marker before removing the bucket, same as AWS.
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "readme" {
  bucket       = aws_s3_bucket.artifacts.id
  key          = "README.txt"
  content      = "Uploaded by Terraform against the local AWS emulator.\n"
  content_type = "text/plain"

  tags = {
    Environment = "emulator"
  }
}

output "s3_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}

output "s3_object_etag" {
  value = aws_s3_object.readme.etag
}

output "app_access_key_id" {
  value = aws_iam_access_key.app.id
}

