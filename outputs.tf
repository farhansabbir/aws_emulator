output "emulator_state_dump" {
  description = "Full state of the Emulated AWS Environment"
  value = {
    # --- Identity & Account Info ---
    identity = {
      account_id = data.aws_caller_identity.current.account_id
      user_arn   = data.aws_caller_identity.current.arn
      user_id    = data.aws_caller_identity.current.user_id
    }

    # --- VPC Details ---
    vpc = {
      id                   = aws_vpc.default_vpc.id
      cidr_block           = aws_vpc.default_vpc.cidr_block
      enable_dns_support   = aws_vpc.default_vpc.enable_dns_support
      enable_dns_hostnames = aws_vpc.default_vpc.enable_dns_hostnames
      instance_tenancy     = aws_vpc.default_vpc.instance_tenancy
      
      # Verify Shadow Resources created by the Emulator
      main_route_table_id = aws_vpc.default_vpc.main_route_table_id
      default_nacl_id     = aws_vpc.default_vpc.default_network_acl_id
      default_sg_id       = aws_vpc.default_vpc.default_security_group_id
      tags                = aws_vpc.default_vpc.tags

      # --- Subnet Details (Fixed Syntax) ---
      # This pulls live data from the aws_subnet resource
      subnet = {
        id                      = aws_subnet.default_subnet.id
        vpc_id                  = aws_subnet.default_subnet.vpc_id
        cidr_block              = aws_subnet.default_subnet.cidr_block
        availability_zone       = aws_subnet.default_subnet.availability_zone
        map_public_ip_on_launch = aws_subnet.default_subnet.map_public_ip_on_launch
      }
    }

    # --- Security Group Deep Dive ---
    security_group = {
      id          = aws_security_group.web.id
      name        = aws_security_group.web.name
      description = aws_security_group.web.description
      vpc_id      = aws_security_group.web.vpc_id
      owner_id    = aws_security_group.web.owner_id
      
      # Verify Ingress Rule Persistence (The "sgr-xxxx" IDs)
      ingress_rules = [
        for rule in aws_security_group.web.ingress : {
          from_port   = rule.from_port
          to_port     = rule.to_port
          protocol    = rule.protocol
          cidr_blocks = rule.cidr_blocks
          description = rule.description
        }
      ]
      
      # Verify Egress (Should be empty if revoked, or default if not)
      egress_rules = [
        for rule in aws_security_group.web.egress : {
          from_port   = rule.from_port
          to_port     = rule.to_port
          protocol    = rule.protocol
          cidr_blocks = rule.cidr_blocks
        }
      ]
    }
  }
}