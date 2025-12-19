locals {
  resource_userdata = <<USER_DATA
#!/usr/bin/env bash
set -ex
exec >> /var/log/user_data.log 2>&1

cat <<SSH_KEY | tee /root/.ssh/${local.ssh_key_name}
${tls_private_key.this.private_key_openssh}
SSH_KEY
chmod 0600 /root/.ssh/${local.ssh_key_name}

echo "${aws_instance.cluster.private_ip}    ${local.cluster_domain}" | tee -a /etc/hosts

while true; do
  if [[ $(curl -w "%%{http_code}" -o NULL -s -k https://${local.cluster_domain}) != "000" ]]; then
    break
  fi
  echo "waiting for Teleport server to be ready"
  sleep 3
done

scp -o StrictHostKeyChecking=no -i /root/.ssh/${local.ssh_key_name} ubuntu@${aws_instance.cluster.private_ip}:/home/ubuntu/teleport /usr/local/bin/teleport
chmod +x /usr/local/bin/teleport

cat <<TELEPORT | tee /etc/teleport.yaml
---
version: v3
teleport:
  nodename: test
  proxy_server: ${local.cluster_domain}:443
  data_dir: /var/lib/teleport
  join_params:
    token_name: "teleport-iam-join-token"
    method: "iam"
  log:
    output: stderr
    severity: DEBUG
    format:
      output: text
auth_service:
  enabled: "no"
ssh_service:
  enabled: "yes"
proxy_service:
  enabled: "no"
app_service:
  enabled: true
  debug_app: true
TELEPORT

cat <<SYSTEMD | tee /usr/lib/systemd/system/teleport.service
[Unit]
Description=Teleport Service
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
EnvironmentFile=-/etc/default/teleport
ExecStart=/usr/local/bin/teleport start --config /etc/teleport.yaml --pid-file=/run/teleport.pid
# systemd before 239 needs an absolute path
ExecReload=/bin/sh -c "exec pkill -HUP -L -F /run/teleport.pid"
PIDFile=/run/teleport.pid
LimitNOFILE=524288

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable teleport
systemctl start teleport

USER_DATA
}

resource "aws_vpc" "resource" {
  cidr_block           = var.cidr.resource
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
}

resource "aws_subnet" "resource" {
  for_each          = { for i, az in data.aws_availability_zones.this.names : i => az }
  vpc_id            = aws_vpc.resource.id
  cidr_block        = cidrsubnet(var.cidr.resource, 3, each.key)
  availability_zone = each.value

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
}

resource "aws_ec2_instance_connect_endpoint" "resource" {
  for_each  = { for i, sb in aws_subnet.resource : i => sb }
  subnet_id = each.value.id
  security_group_ids = [aws_security_group.resource.id]

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
}

resource "aws_route_table_association" "resource" {
  for_each       = { for i, sb in aws_subnet.resource : i => sb }
  route_table_id = aws_vpc.resource.default_route_table_id
  subnet_id      = each.value.id
}

resource "aws_security_group" "resource" {
  name        = "${local.tags.Name}-resource-sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.resource.id

  ingress {
    cidr_blocks = [var.cidr.cluster]
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
  }

  egress {
    cidr_blocks = [var.cidr.cluster]
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
  }

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource-sg", role : "aws-network" })
}

resource "aws_security_group" "sts" {
  name        = "${local.tags.Name}-sts-sg"
  description = "Allow HTTPS from EC2 to STS VPC endpoint"
  vpc_id      = aws_vpc.resource.id

  ingress {
    description     = "HTTPS from EC2"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.resource.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource-sts-sg", role : "aws-network" })
}

resource "aws_vpc_endpoint" "this" {
  vpc_id            = aws_vpc.resource.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.sts"
  vpc_endpoint_type = "Interface"
  auto_accept       = true

  security_group_ids  = [aws_security_group.sts.id]
  subnet_ids          = [for sb in aws_subnet.resource : sb.id]
  private_dns_enabled = true

  tags = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
}

data "aws_iam_policy_document" "resource" {
  statement {
    effect = "Allow"

    actions = [
      "ssm:GetParameters",
      "ssm:GetParameter"
    ]

    resources = [
      aws_ssm_parameter.ssh_priv_key.arn,
    ]
  }

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

data "aws_iam_policy_document" "resource_assume_role" {
  statement {
    effect = "Allow"

    principals {
      identifiers = ["ec2.amazonaws.com"]
      type        = "Service"
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_policy" "resource" {
  name   = "${local.tags.Name}-resource-policy"
  policy = data.aws_iam_policy_document.resource.json
  tags   = merge(local.tags, { Name : "${local.tags.Name}-resource-policy", role : "aws-network" })
}

resource "aws_iam_role" "resource" {
  name               = "${local.tags.Name}-resource-role"
  assume_role_policy = data.aws_iam_policy_document.resource_assume_role.json
  tags               = merge(local.tags, { Name : "${local.tags.Name}-resource-role", role : "aws-network" })
}

resource "aws_iam_instance_profile" "resource" {
  name = "${local.tags.Name}-resource-profile"
  role = aws_iam_role.resource.name
  tags = merge(local.tags, { Name : "${local.tags.Name}-resource-profile", role : "aws-network" })
}

resource "aws_instance" "resource" {
  ami                         = data.aws_ami.this.id
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.resource[0].id
  key_name                    = aws_key_pair.this.key_name
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.resource.id]
  iam_instance_profile        = aws_iam_instance_profile.resource.name
  metadata_options {
    instance_metadata_tags = "enabled"
  }

  root_block_device {
    volume_size = 8
  }

  user_data_base64 = base64encode(local.resource_userdata)

  tags        = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
  volume_tags = merge(local.tags, { Name : "${local.tags.Name}-resource", role : "aws-network" })
}