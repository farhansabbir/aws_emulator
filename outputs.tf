output "emulator_state_dump" {
  description = "Full state of the Emulated AWS Environment (JSON formatted)"
  # The 'value' is wrapped in jsonencode for clean printing
  value = {
    # --- Identity ---
    identity = {
      account_id = data.aws_caller_identity.current.account_id
      user_arn   = data.aws_caller_identity.current.arn
    }

    # --- Instance ---
    instance = {
      id          = aws_instance.app_server.id
      private_ip  = aws_instance.app_server.private_ip
      public_ip   = aws_instance.app_server.public_ip
      subnet_id   = aws_instance.app_server.subnet_id
      security_groups = aws_instance.app_server.vpc_security_group_ids
      tags        = aws_instance.app_server.tags
    }

    # --- VPC & Subnet ---
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
      }
      ]
    }
  }
}