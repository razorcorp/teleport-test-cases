terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.22.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "4.1.0"
    }
  }
}

data "aws_availability_zones" "this" {
  state = "available"
}

resource "tls_private_key" "this" {
  algorithm = "ED25519"
}

resource "local_sensitive_file" "this" {
  content  = tls_private_key.this.private_key_openssh
  filename = "${path.root}/id_${lower(tls_private_key.this.algorithm)}"
}

resource "aws_key_pair" "this" {
  key_name   = "${var.tags.Name}-key"
  public_key = tls_private_key.this.public_key_openssh

  tags = var.tags
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = var.tags
}

resource "aws_subnet" "this" {
  for_each          = { for i, az in data.aws_availability_zones.this.names : i => az }
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.cidr, 3, each.key)
  availability_zone = each.value

  tags = var.tags
}

resource "aws_route_table_association" "this" {
  for_each       = { for i, sb in aws_subnet.this : i => sb }
  route_table_id = aws_vpc.this.default_route_table_id
  subnet_id      = each.value.id
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = var.tags
}

resource "aws_route" "this" {
  route_table_id         = aws_vpc.this.default_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_security_group" "this" {
  name        = "${var.tags.Name}-sg"
  vpc_id      = aws_vpc.this.id

  egress {
    cidr_blocks = ["0.0.0.0/0"]
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
  }

  ingress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
  }

  tags = var.tags
}

data "aws_iam_policy_document" "this" {

  statement {
    effect = "Allow"

    actions = ["iam:PassRole", "sts:GetCallerIdentity"]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      values   = ["ec2.amazonaws.com"]
      variable = "iam:PassedToService"
    }

  }
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      identifiers = ["ec2.amazonaws.com"]
      type        = "Service"
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_policy" "this" {
  name   = "${var.tags.Name}-policy"
  policy = data.aws_iam_policy_document.this.json
  tags   = var.tags
}

resource "aws_iam_role" "this" {
  name               = "${var.tags.Name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = var.tags
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.tags.Name}-profile"
  role = aws_iam_role.this.name
  tags = var.tags
}

resource "aws_instance" "this" {
  ami                         = var.instance.ami_id
  instance_type               = var.instance.type
  subnet_id                   = aws_subnet.this[0].id
  key_name                    = aws_key_pair.this.key_name
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.this.id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  metadata_options {
    instance_metadata_tags = "enabled"
  }

  root_block_device {
    volume_size = var.instance.size
  }
  tags        = var.tags
  volume_tags = var.tags
}

output "ip" {
  value = aws_instance.this.public_ip
}

output "key_name" {
  value = local_sensitive_file.this.filename
}