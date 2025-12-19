locals {
  teleport_yaml = <<TELEPORT_YAML
---
version: v3
teleport:
  nodename: ${local.cluster_domain}
  data_dir: /var/lib/teleport
  join_params:
    token_name: ""
    method: token
  log:
    output: stderr
    severity: DEBUG
    format:
      output: text
  storage:
    type: sqlite
    audit_events_uri:
      - 'file:///var/lib/teleport/log'
    audit_retention_period: 14d
auth_service:
  enabled: "yes"
  listen_addr: 0.0.0.0:3025
  cluster_name: "${local.cluster_domain}"
  license_file: /var/lib/teleport/license.pem
  proxy_listener_mode: multiplex

  authentication:
    second_factors: ["webauthn", "otp"]
    passwordless: true
    headless: true
    connector_name: passwordless
    webauthn:
      rp_id: ${local.cluster_domain}
ssh_service:
  enabled: "no"
proxy_service:
  enabled: "yes"
  web_listen_addr: 0.0.0.0:443
  public_addr: "${local.cluster_domain}:443"
  https_keypairs:
    - key_file: /etc/teleport/ssl/private.pem
      cert_file: /etc/teleport/ssl/fullchain.pem
  https_keypairs_reload_interval: 0s
  acme: { }
TELEPORT_YAML

  iam_token = <<IAM_TOKEN
kind: token
version: v2
metadata:
  name: teleport-iam-join-token
spec:
  roles: [Node, App]
  join_method: iam
  allow:
    - aws_account: "${data.aws_caller_identity.this.account_id}"
IAM_TOKEN

  cluster_userdata = <<USER_DATA
${local.installation_base}

cp $(which teleport) /home/ubuntu/teleport
chown ubuntu: /home/ubuntu/teleport


aws ssm get-parameter --name ${local.teleport.license} | jq -r '.Parameter.Value' | tee /var/lib/teleport/license.pem
aws ssm get-parameter --name ${aws_ssm_parameter.teleport_yaml.name} | jq -r '.Parameter.Value' | tee /etc/teleport.yaml
aws ssm get-parameter --name ${aws_ssm_parameter.iam_token.name} | jq -r '.Parameter.Value' | tee iam_token.yaml

systemctl enable teleport
systemctl start teleport

while true; do
  if [[ $(curl -w "%%{http_code}" -o NULL -s -k https://127.0.0.1) != "000" ]]; then
    break
  fi
  echo "waiting for Teleport service to be ready"
  sleep 3
done

tctl create -f iam_token.yaml

INIT_URL=$(tctl users add teleport-admin --roles=editor,access --logins=root,ubuntu)
aws ssm put-parameter --overwrite --name "${aws_ssm_parameter.cluster.name}" --value "$(echo $INIT_URL)"
USER_DATA
}

resource "aws_ssm_parameter" "teleport_yaml" {
  name  = "/teleport/${local.cluster_domain}/teleport.yaml"
  type  = "String"
  tier  = "Advanced"
  value = local.teleport_yaml

  tags = local.tags
}

resource "aws_ssm_parameter" "iam_token" {
  name  = "/teleport/${local.cluster_domain}/iam_token.yaml"
  type  = "String"
  tier  = "Standard"
  value = local.iam_token

  tags = local.tags
}

resource "aws_ssm_parameter" "cluster" {
  name  = "/teleport/${local.cluster_domain}/initial_user"
  type  = "String"
  tier  = "Standard"
  value = "will be populated by instance"

  lifecycle {
    ignore_changes = [value]
  }

  tags = local.tags
}


resource "aws_vpc" "cluster" {
  cidr_block = var.cidr.cluster
}

resource "aws_internet_gateway" "cluster" {
  vpc_id = aws_vpc.cluster.id
  tags   = local.tags
}

resource "aws_route" "igw" {
  route_table_id         = aws_vpc.cluster.default_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.cluster.id
}

resource "aws_subnet" "cluster" {
  for_each                = { for i, az in data.aws_availability_zones.this.names : i => az }
  vpc_id                  = aws_vpc.cluster.id
  cidr_block              = cidrsubnet(var.cidr.cluster, 3, each.key)
  availability_zone       = each.value
  map_public_ip_on_launch = true

  tags = local.tags
}

resource "aws_route_table_association" "cluster" {
  for_each       = { for i, sb in aws_subnet.cluster : i => sb }
  route_table_id = aws_vpc.cluster.default_route_table_id
  subnet_id      = each.value.id
}

resource "aws_security_group" "cluster" {
  name        = "${local.tags.Name}-cluster-sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.cluster.id

  egress {
    cidr_blocks = ["0.0.0.0/0"]
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
  }

  ingress {
    cidr_blocks = [var.cidr.resource]
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

  ingress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
  }

  tags = local.tags
}

data "aws_route53_zone" "cluster" {
  name = "${var.domain}."
}

resource "aws_acm_certificate" "cluster" {
  domain_name = local.cluster_domain
  subject_alternative_names = [
    "*.${local.cluster_domain}",
  ]
  validation_method = "DNS"
  options {
    export = "ENABLED"
  }

  tags = local.tags
}

resource "aws_route53_record" "cluster" {
  for_each = {
    for dvo in aws_acm_certificate.cluster.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.cluster.zone_id
}

resource "aws_acm_certificate_validation" "cluster" {
  certificate_arn         = aws_acm_certificate.cluster.arn
  validation_record_fqdns = [for record in aws_route53_record.cluster : record.fqdn]
}

data "aws_iam_policy_document" "cluster" {
  statement {
    effect = "Allow"

    actions = [
      "ssm:PutParameter",
      "ssm:GetParameters",
      "ssm:GetParameter"
    ]

    resources = [
      aws_ssm_parameter.cluster.arn,
      aws_ssm_parameter.teleport_yaml.arn,
      aws_ssm_parameter.iam_token.arn,
      "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.this.account_id}:parameter/teleport/license/prav/license.pem",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "acm:ExportCertificate",
    ]

    resources = [
      aws_acm_certificate_validation.cluster.certificate_arn
    ]
  }

  statement {
    effect = "Allow"

    actions = ["iam:PassRole"]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      values   = ["ec2.amazonaws.com"]
      variable = "iam:PassedToService"
    }

  }
}

data "aws_iam_policy_document" "cluster_assume_role" {
  statement {
    effect = "Allow"

    principals {
      identifiers = ["ec2.amazonaws.com"]
      type        = "Service"
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_policy" "cluster" {
  name   = "${local.tags.Name}-cluster-policy"
  policy = data.aws_iam_policy_document.cluster.json
  tags   = local.tags
}

resource "aws_iam_role" "cluster" {
  name               = "${local.tags.Name}-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume_role.json
  tags               = local.tags
}

resource "aws_iam_instance_profile" "cluster" {
  name = "${local.tags.Name}-cluster-profile"
  role = aws_iam_role.cluster.name
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  policy_arn = aws_iam_policy.cluster.arn
  role       = aws_iam_role.cluster.name
}

resource "aws_instance" "cluster" {
  ami                         = data.aws_ami.this.id
  instance_type               = "t3a.micro"
  subnet_id                   = aws_subnet.cluster[0].id
  key_name                    = aws_key_pair.this.key_name
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.cluster.id]
  iam_instance_profile        = aws_iam_instance_profile.cluster.name
  metadata_options {
    instance_metadata_tags = "enabled"
  }

  root_block_device {
    volume_size = 8
  }

  user_data_base64 = base64encode(local.cluster_userdata)

  tags        = merge(local.tags, { Name : "${local.tags.Name}-cluster", role : "corp-network" })
  volume_tags = local.tags
}

resource "aws_route53_record" "cluster_ip" {
  zone_id = data.aws_route53_zone.cluster.zone_id
  name    = local.cluster_domain
  type    = "A"
  ttl     = 60
  records = [aws_instance.cluster.public_ip]
}

output "cluster_ip" {
  value = aws_instance.cluster.public_ip
}