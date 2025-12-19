terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.22.1"
    }
    http = {
      source  = "hashicorp/http"
      version = "3.5.0"
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

variable "domain" {
  description = "Domain from Route53 to use with clusters"
}

variable "cidr" {
  description = "VPC CIDR ranges"
  type = object({
    cluster : string
    resource : string
  })
}

variable "ami" {
  description = "Instance AMI lookup values"
  type = object({
    owner : string
    name_pattern : string
  })

  default = {
    name_pattern = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
    owner        = "099720109477"
  }
}

variable "teleport" {
  description = "Teleport specific configuration options"
  type = object({
    version : string
    license_path : string
    cluster_domain : string
  })
}

variable "tags" {
  description = "List of resource tags"
  type        = map(string)
}

data "aws_region" "current" {}

data "aws_caller_identity" "this" {}

data "http" "teleport_version" {
  count = (var.teleport.version == "latest") ? 1 : 0
  url   = "https://api.github.com/repos/gravitational/teleport/releases/latest"

  # Optional request headers
  request_headers = {
    Accept     = "application/vnd.github+json"
    User-Agent = "terraform"
  }
}

resource "random_password" "this" {
  length  = 8
  special = false

}

resource "tls_private_key" "this" {
  algorithm = "ED25519"
}

locals {
  ssh_key_name   = "id_${lower(tls_private_key.this.algorithm)}"
  tags           = var.tags
  cluster_domain = var.teleport.cluster_domain
  teleport = {
    edition        = "enterprise"
    version        = (var.teleport.version == "latest") ? trimprefix(jsondecode(data.http.teleport_version[0].response_body).tag_name, "v") : var.teleport.version
    license        = var.teleport.license_path
    encryption_key = random_password.this.result
  }
  installation_base = <<BASE
#!/usr/bin/env bash
set -ex
exec >> /var/log/user_data.log 2>&1

source /etc/os-release

apt-get update
apt-get upgrade -y

apt-get install -y curl software-properties-common gnupg2 ca-certificates openssl jq unzip python3-venv vim

cd /tmp/
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -o awscliv2.zip
sudo ./aws/install > /dev/null 2>&1

# Get AWS credentials for interacting with AWS resources
TOKEN=$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
REGION=$(curl -fsSL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')
ROLE=$(curl -fsSL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials)
CREDS=$(curl -fsSL -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')
export AWS_DEFAULT_REGION=$REGION

# Get SSL certificate from ACM
mkdir -p /etc/teleport/ssl || rm -rf /etc/teleport/ssl/*
cert_json=$(aws acm export-certificate --certificate-arn "${aws_acm_certificate_validation.cluster.certificate_arn}" --passphrase "${local.teleport.encryption_key}" --cli-binary-format raw-in-base64-out)
echo -n $cert_json | jq -r '.Certificate' > /etc/teleport/ssl/certificate.pem
echo -n $cert_json | jq -r '.CertificateChain' > /etc/teleport/ssl/chain.pem
echo -n $cert_json | jq -r '.Certificate + .CertificateChain' > /etc/teleport/ssl/fullchain.pem
echo -n $cert_json | jq -r '.PrivateKey' | openssl pkcs8 -passin pass:${local.teleport.encryption_key} > /etc/teleport/ssl/private.pem

curl https://cdn.teleport.dev/install.sh | bash -s ${local.teleport.version} ${local.teleport.edition}
install -m 0755 -d /var/lib/teleport/
  BASE
}

data "aws_availability_zones" "this" {
  state = "available"
}

resource "aws_key_pair" "this" {
  key_name   = "${local.tags.Name}-key"
  public_key = tls_private_key.this.public_key_openssh

  tags = local.tags
}

resource "aws_ssm_parameter" "ssh_priv_key" {
  name  = "/teleport/${local.cluster_domain}/${lower(replace(aws_key_pair.this.key_name, "-", "_"))}"
  type  = "String"
  tier  = "Advanced"
  value = tls_private_key.this.private_key_openssh

  tags = local.tags
}

data "aws_ami" "this" {
  most_recent = true

  filter {
    name   = "name"
    values = [var.ami.name_pattern]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = [var.ami.owner]
}

resource "aws_vpc_peering_connection" "this" {
  peer_vpc_id = aws_vpc.resource.id
  vpc_id      = aws_vpc.cluster.id
  auto_accept = true

  tags = local.tags
}

resource "aws_route" "cluster_resource" {
  route_table_id            = aws_vpc.cluster.default_route_table_id
  destination_cidr_block    = aws_vpc.resource.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.this.id
}

resource "aws_route" "resource_cluster" {
  route_table_id            = aws_vpc.resource.default_route_table_id
  destination_cidr_block    = aws_vpc.cluster.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.this.id
}

resource "local_sensitive_file" "ssh_priv_key" {
  content  = tls_private_key.this.private_key_openssh
  filename = "${path.root}/${local.ssh_key_name}"
}

output "init_login" {
  value = aws_ssm_parameter.cluster.name
}