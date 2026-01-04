# Lightweight AWS Emulator for Terraform

A lightweight, in-memory AWS API emulator written in Python (Flask). This tool mocks the behavior of key AWS services (EC2, VPC, Networking) to allow for fast, cost-free local testing of Terraform configurations.

It strictly adheres to the AWS XML API structure to satisfy the HashiCorp Terraform AWS Provider.

🚀 Features

Compute: EC2 Instances (Run, Describe, Terminate, Attribute modification).

Networking: VPCs, Subnets (Public/Private), Internet Gateways, NAT Gateways.

Security: Security Groups, Ingress/Egress rules, Network ACLs.

IP Management: Elastic IPs (EIP) and Public IP auto-assignment pools.

Tagging: Full resource tagging support.

📦 Prerequisites

Python 3.x

Terraform

pip

🛠️ Quick Start

1. Start the Emulator

Run the Python server. This listens on port 4566 (simulating LocalStack/AWS endpoints).

# Set up virtual environment
python -m venv venv && source venv/bin/activate

# Install dependencies (Flask)
`bash
pip install flask
`bash

# Run the emulator
`bash
python3 main.py
`


2. Run Terraform

Open a new terminal window and run your Terraform infrastructure code against the local emulator.

terraform init
terraform apply -auto-approve


📄 Configuration (main.tf)

Save the following code as main.tf. This configuration sets up a complete VPC network with public/private subnets, gateways, and a web server instance.

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = false
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
    s3             = "[http://s3.localhost.localstack.cloud:4566](http://s3.localhost.localstack.cloud:4566)"
    secretsmanager = "http://localhost:4566"
    ses            = "http://localhost:4566"
    sns            = "http://localhost:4566"
    sqs            = "http://localhost:4566"
    ssm            = "http://localhost:4566"
    stepfunctions  = "http://localhost:4566"
    sts            = "http://localhost:4566"
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
  
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name = "Emulator-Instance"
  }
}

data "aws_caller_identity" "current" {}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "example" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.default_subnet.id
}

# --- Outputs ---

output "instance_ip" {
  value = aws_instance.app_server.private_ip
}

output "outbound_ip_address" {
  value = aws_eip.nat.public_ip
}

output "emulator_state_dump" {
  description = "Full state of the Emulated AWS Environment (JSON formatted)"
  value = {
    identity = {
      account_id = data.aws_caller_identity.current.account_id
      user_arn   = data.aws_caller_identity.current.arn
    }
    instance = {
      id          = aws_instance.app_server.id
      private_ip  = aws_instance.app_server.private_ip
      public_ip   = aws_instance.app_server.public_ip
      subnet_id   = aws_instance.app_server.subnet_id
      security_groups = aws_instance.app_server.vpc_security_group_ids
      tags        = aws_instance.app_server.tags
    }
    vpc = {
      id         = aws_vpc.default_vpc.id
      cidr       = aws_vpc.default_vpc.cidr_block
      subnet     = [{
        id   = aws_subnet.default_subnet.id
        cidr = aws_subnet.default_subnet.cidr_block
        az   = aws_subnet.default_subnet.availability_zone
        public_ip_on_launch = aws_subnet.default_subnet.map_public_ip_on_launch
      },
      {
        id   = aws_subnet.private_subnet.id
        cidr = aws_subnet.private_subnet.cidr_block
        az   = aws_subnet.private_subnet.availability_zone
        public_ip_on_launch = aws_subnet.private_subnet.map_public_ip_on_launch
      }]
      IGW = {
        id = aws_internet_gateway.default_igw.id
      }
    }
  }
}


✅ Expected Output

When running terraform apply, the emulator correctly handles the creation order (VPC -> Subnet -> Security Groups -> Instances) and resource linking.

aws_eip.nat: Creating...
aws_vpc.default_vpc: Creating...
aws_eip.nat: Creation complete after 0s [id=eipalloc-893f2a2d]
aws_vpc.default_vpc: Creation complete after 0s [id=vpc-caae0bfb]
aws_internet_gateway.default_igw: Creating...
aws_subnet.private_subnet: Creating...
aws_security_group.web: Creating...
aws_subnet.default_subnet: Creating...
aws_subnet.private_subnet: Creation complete after 0s [id=subnet-1df33a73]
aws_internet_gateway.default_igw: Creation complete after 0s [id=igw-f180c51e]
aws_security_group.web: Creation complete after 0s [id=sg-848fd011]
aws_security_group_rule.web_allow_http_from_any: Creating...
aws_security_group_rule.web_allow_http_from_any: Creation complete after 0s [id=sgrule-4202308986]
aws_subnet.default_subnet: Still creating... [00m10s elapsed]
aws_subnet.default_subnet: Creation complete after 10s [id=subnet-4fe0ce8b]
aws_nat_gateway.example: Creating...
aws_instance.app_server: Creating...
aws_nat_gateway.example: Creation complete after 0s [id=nat-783805c0]
aws_instance.app_server: Still creating... [00m10s elapsed]
aws_instance.app_server: Creation complete after 10s [id=i-529eb071]

Apply complete! Resources: 9 added, 0 changed, 0 destroyed.

Outputs:

emulator_state_dump = {
  "identity" = {
    "account_id" = "123456789012"
    "user_arn" = "arn:aws:iam::123456789012:user/emulator"
  }
  "instance" = {
    "id" = "i-529eb071"
    "private_ip" = "10.0.1.10"
    "public_ip" = "203.0.113.1"
    "security_groups" = toset([
      "sg-848fd011",
    ])
    "subnet_id" = "subnet-4fe0ce8b"
    "tags" = tomap({})
  }
  "vpc" = {
    "IGW" = {
      "id" = "igw-f180c51e"
    }
    "cidr" = "10.0.0.0/16"
    "id" = "vpc-caae0bfb"
    "subnet" = [
      {
        "az" = "us-east-1a"
        "cidr" = "10.0.10.0/24"
        "id" = "subnet-4fe0ce8b"
        "public_ip_on_launch" = true
      },
      {
        "az" = "us-east-1a"
        "cidr" = "10.0.100.0/24"
        "id" = "subnet-1df33a73"
        "public_ip_on_launch" = false
      },
    ]
  }
}
instance_ip = "10.0.1.10"
outbound_ip_address = "52.99.100.1"
