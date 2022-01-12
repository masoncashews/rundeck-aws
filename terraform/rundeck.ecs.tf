terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

#####################
#Variables
#####################
#AWS credentials file with access keys
variable "aws_credentials_file" {
  type = string
}

#AWS region to use
variable "aws_region" {
  type = string
}

#AWS Profile to use... can be default
variable "aws_profile" {
  type = string
}

#What project is this deployment for?  Used for names and tags
variable "project" {
  type = string
}

#Create a bastion in the ALB and open ssh to the instance
#also allow SSH into the mgmt sg
variable "create_bastion" {
  type    = bool
  default = false
}

#Map of different settings that would be specific to each rundeck environment
variable "environment_configuration" {
  #VPC and Subnet information of the environment
  type = map(any)
  default = {
    #all have to be arrays because I need arrays for a couple.
    #ID of the target VPC
    vpc_id = [""]
    #ID array of public subnets
    subnets_public = [""]
    #ID array of private subnets
    subnets_private = [""]
    #ARN of SSL in Cert Manager
    alb_ssl_cert_arn = [""]
    #Domain Name - used in configs not so much for resources
    domain_name = [""]
    #Environment name, used for tagging and what not.
    environment_name = [""]
    #Rundeck API Key - used by ALB to protect webhooks - GUID preferred
    rundeck_webhook_api_key = [""]
    #Rundeck rundeck.storage.converter.1.config.password,rundeck.config.storage.converter.1.config.password values
    rundeck_storage_converter_password = [""]
    #Create external ALB connections (true/false)
    #Will create ingress rules on security groups.
    externally_accessible = [""]
    #Allow Port 80 incoming from the internet (true/false)
    #Will create ingress rules on security groups and a redirect on the ALB
    allow_incoming_port_80 = [""]
    #Rundeck still has the old login screen available even during preauth
    #Its disabled by the ALB, but just in case you can access the screen with a /user/login?bypass=<this value>
    bypass_login_redirect_value = [""]
  }
}

#Map of different settings for the EC2 launch instances
variable "ec2_configuration" {
  #ec2 launch config stuff
  type = map(any)
  default = {
    #Instance size to be used for the launch template
    instance_type = [""]
    #Disk Type
    volume_type = [""]
    #Disk size in GBs
    volume_size = []
    #Keypair/key_name
    key_name = [""]
  }
}

#Map of different settings for RDS
variable "rds_configuration" {
  type = map(any)
  #DB Name for postgres used for configs and resources
  default = {
    db_name = ""
    #Username for postgres used for configs and resources
    db_username = ""
    #Password for postgres used for configs and resources
    db_password = ""
    #Storage size for instance in GB
    storage_size = 0
  }
}

#Map of different settings for ECS/Fargate pieces
variable "ecs_configuration" {
  type = map(any)
  default = {
    #Username for repository
    docker_repo_username = ""
    #Password/token for repository
    docker_repo_password = ""
    #Repo image path and tag, what's the docker pull
    docker_repo_image = ""
    #how much memory to allocate to the ecs service
    service_memory = 0
    #how much cpu to allocate to the ecs service
    service_cpu = ""
    #Shared files path, where to mount EFS
    shared_files_path = ""
    #Enable ECS Exec, includes permissions and configurations
    ecs_exec_enabled = false
  }
}

#Map of different settings for SSO/Vouch-Proxy
variable "sso_configuration" {
  type = map(any)
  default = {
    #oAuth client id
    client_id = ""
    #oAuth client secret
    client_secret = ""
    #oAuth auth URL
    auth_url = ""
    #oAuth token URL
    token_url = ""
    #oAuth logout url
    logout_url = ""
    #adfs Relying Party ID
    relying_party_id = ""
    #Delay before starting vouch
    vouch_delay = ""
  }
}
#####################
#Locals - only way to bring tagging into the ASG so only used for default tags.
#####################
locals {
  default_tags = {
    environment   = var.environment_configuration["environment_name"][0]
    business-unit = "SRC"
    department    = "SRE"
    project       = "rundeck"
    generated-by  = "terraform"
  }
}

#####################
#Datasources
#####################
#Get the latest AML2 x86 AMI for EBS
data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-ebs"]
  }
}

#####################
#Providers
#####################
provider "aws" {
  shared_credentials_file = var.aws_credentials_file
  profile                 = var.aws_profile
  region                  = var.aws_region
  default_tags {
    tags = local.default_tags
  }
}

#####################
#Security groups
#####################
#Security Group for the rundeck nodes
resource "aws_security_group" "rundeck-mgmt-sg" {
  vpc_id      = var.environment_configuration["vpc_id"][0]
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "mgmt-sg"])
  description = "Security Group for Rundeck Instances in ${var.environment_configuration["environment_name"][0]}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "mgmt-sg"])
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}


#Security Group rule for the rundeck nodes
#adding rules this way because of the bastion condition later.
resource "aws_security_group_rule" "rundeck-allow-mgmt-80-alb" {
  type                     = "ingress"
  description              = "Allow traffic from ALB (80)"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rundeck-alb-sg.id
  security_group_id        = aws_security_group.rundeck-mgmt-sg.id
}

#Security Group rule for the rundeck nodes
#adding rules this way because of the bastion condition later.
resource "aws_security_group_rule" "rundeck-allow-mgmt-80-self" {
  type              = "ingress"
  description       = "Allow traffic from self (80)"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.rundeck-mgmt-sg.id
}

#Security group for the ALB service interface
resource "aws_security_group" "rundeck-alb-sg" {
  vpc_id      = var.environment_configuration["vpc_id"][0]
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "alb-sg"])
  description = "Security Group for rundeck ALB in ${var.environment_configuration["environment_name"][0]}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "alb-sg"])
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

#SG Rule to allow self 443 connections to the load balancer
resource "aws_security_group_rule" "rundeck-allow-alb-443-self" {
  type              = "ingress"
  description       = "Allow incoming HTTPS traffic (443)"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.rundeck-alb-sg.id
}

#SG Rule (conditional) to allow external 443 connections to the load balancer
resource "aws_security_group_rule" "rundeck-allow-alb-443-external" {
  count             = (var.environment_configuration["externally_accessible"][0] == "true") ? 1 : 0
  type              = "ingress"
  description       = "Allow incoming HTTPS traffic (443)"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rundeck-alb-sg.id
}

#SG Rule (conditional) to allow external port 80 connections to the load balancer
resource "aws_security_group_rule" "rundeck-allow-alb-80-external" {
  count             = ((var.environment_configuration["externally_accessible"][0] == "true") && (var.environment_configuration["allow_incoming_port_80"][0] == "true")) ? 1 : 0
  type              = "ingress"
  description       = "Allow incoming HTTP traffic (80)"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rundeck-alb-sg.id
}

#SG Rule (conditional) to allow port 80 connections to the load balancer from itself
resource "aws_security_group_rule" "rundeck-allow-alb-80-self" {
  count             = ((var.environment_configuration["externally_accessible"][0] == "true") && (var.environment_configuration["allow_incoming_port_80"][0] == "true")) ? 1 : 0
  type              = "ingress"
  description       = "Allow self HTTP traffic (80)"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  self              = true
  security_group_id = aws_security_group.rundeck-alb-sg.id
}

#Security group for the EFS service interface
resource "aws_security_group" "rundeck-efs-sg" {
  vpc_id      = var.environment_configuration["vpc_id"][0]
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "efs-sg"])
  description = "Security Group for Rundecks EFS in ${var.environment_configuration["environment_name"][0]}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "efs-sg"])
  }

  ingress {
    security_groups = [aws_security_group.rundeck-mgmt-sg.id]
    description     = "Allow traffic from rundeck mgmt for EFS (2049)"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

#Security group for postgres endpoints
resource "aws_security_group" "rundeck-db-sg" {
  vpc_id      = var.environment_configuration["vpc_id"][0]
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "db-sg"])
  description = "Security Group for Rundeck RDS in ${var.environment_configuration["environment_name"][0]}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "db-sg"])
  }

  ingress {
    security_groups = [aws_security_group.rundeck-mgmt-sg.id]
    description     = "Allow traffic from rundeck mgmt for RDS Postgres (5432)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

#####################
#Bastion (conditional) - host and related security group pieces
#####################
resource "aws_instance" "rundeck-bastion" {
  count = var.create_bastion ? 1 : 0
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "bastion"])
  }
  instance_type               = "t2.micro"
  subnet_id                   = var.environment_configuration["subnets_public"][0]
  vpc_security_group_ids      = [aws_security_group.rundeck-bastion-sg[0].id]
  ami                         = data.aws_ami.amazon-linux-2.id
  key_name                    = var.ec2_configuration["key_name"][0]
  associate_public_ip_address = true

  root_block_device {
    delete_on_termination = true
    encrypted             = true
    volume_type           = "gp2"
    volume_size           = 10
    tags                  = local.default_tags
  }
}

resource "aws_security_group" "rundeck-bastion-sg" {
  count       = var.create_bastion ? 1 : 0
  vpc_id      = var.environment_configuration["vpc_id"][0]
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "bastion-sg"])
  description = "Security group for Rundeck Bastion in ${var.environment_configuration["environment_name"][0]}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "bastion-sg"])
  }

  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow traffic to bastion hosts"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group_rule" "rundeck-allow-bastion-ssh" {
  count                    = var.create_bastion ? 1 : 0
  type                     = "ingress"
  description              = "Allow SSH from bastion"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rundeck-bastion-sg[0].id
  security_group_id        = aws_security_group.rundeck-mgmt-sg.id
}

#####################
#ALB & Target Groups
#####################
#ALB, to front the Auto Scale Group/TargetGroup
resource "aws_lb" "rundeck-alb" {
  name               = join("-", [var.project, var.environment_configuration["environment_name"][0], "alb"])
  load_balancer_type = "application"
  subnets            = var.environment_configuration["subnets_public"]
  security_groups    = [aws_security_group.rundeck-alb-sg.id]
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "alb"])
  }
}

#Listener for 443, will need other rules for things.. but the default will be send to rundeck
resource "aws_lb_listener" "rundeck-alb-https-listener" {
  load_balancer_arn = aws_lb.rundeck-alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.environment_configuration["alb_ssl_cert_arn"][0]
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.rundeck-target-group.arn
    order            = 50000 #Make it last to be eval.
  }
}

#Listener rule for ajax calls rundeck uses in its UI
resource "aws_lb_listener_rule" "rundeck-alb-https-listener-rule-allow-ajax" {
  listener_arn = aws_lb_listener.rundeck-alb-https-listener.arn
  priority     = 10
  condition {
    path_pattern {
      values = ["/api/*/project/*/webhook/*"]
    }
  }

  condition {
    http_header {
      http_header_name = "x-rundeck-ajax"
      values           = ["true"]
    }
  }

  condition {
    http_header {
      http_header_name = "x-rundeck-token-uri"
      values           = ["/webhook/admin"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.rundeck-target-group.arn
  }
}

#Listener rule for webhooks on rundeck
resource "aws_lb_listener_rule" "rundeck-alb-https-listener-rule-allow-webhook" {
  listener_arn = aws_lb_listener.rundeck-alb-https-listener.arn
  priority     = 20
  condition {
    path_pattern {
      values = ["/api/*/webhook/*"]
    }
  }

  condition {
    http_header {
      http_header_name = "x-api-key"
      values           = [var.environment_configuration["rundeck_webhook_api_key"][0]]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.rundeck-target-group.arn
  }
}

#Listener rule for webhooks on rundeck with invalid API key
resource "aws_lb_listener_rule" "rundeck-alb-https-listener-rule-deny-webhook" {
  listener_arn = aws_lb_listener.rundeck-alb-https-listener.arn
  priority     = 30
  condition {
    path_pattern {
      values = ["/api/*/webhook/*"]
    }
  }
  action {
    type = "redirect"
    redirect {
      status_code = "HTTP_302"
      path        = "/"
    }
  }
}

#Listener rule to allow user login with querystring variable.  A just in case thing.
resource "aws_lb_listener_rule" "rundeck-alb-https-listener-rule-bypass-redirect-user-login" {
  listener_arn = aws_lb_listener.rundeck-alb-https-listener.arn
  priority     = 40
  condition {
    path_pattern {
      values = ["/users/login/*", "/users/login"]
    }
  }

  condition {
    query_string {
      key   = "bypass"
      value = var.environment_configuration["bypass_login_redirect_value"][0]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.rundeck-target-group.arn
  }
}

#Listener rule to prevent user login screen
resource "aws_lb_listener_rule" "rundeck-alb-https-listener-rule-redirect-user-login" {
  listener_arn = aws_lb_listener.rundeck-alb-https-listener.arn
  priority     = 50
  condition {
    path_pattern {
      values = ["/users/login/*", "/users/login"]
    }
  }
  action {
    type = "redirect"
    redirect {
      status_code = "HTTP_302"
      path        = "/"
    }
  }
}

#Listener for 80 (conditional), will redirect to SSL
resource "aws_lb_listener" "rundeck-alb-http-listener" {
  count             = (var.environment_configuration["allow_incoming_port_80"][0] == "true") ? 1 : 0
  load_balancer_arn = aws_lb.rundeck-alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type  = "redirect"
    order = 1
    redirect {
      status_code = "HTTP_302"
      port        = 443
      protocol    = "HTTPS"
    }
  }
}

#ALB Target group, will encompass the auto scaling group istances
resource "aws_lb_target_group" "rundeck-target-group" {
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "tg"])
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.environment_configuration["vpc_id"][0]
  target_type = "ip"

  health_check {
    healthy_threshold   = 2
    interval            = 60
    matcher             = "200-399"
    path                = "/"
    port                = 80
    unhealthy_threshold = 5
  }

  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "tg"])
  }
}

#####################
#EFS for central files
#####################
#EFS file system to be mounted and reused.
resource "aws_efs_file_system" "rundeck-efs" {
  creation_token = join("-", [var.project, var.environment_configuration["environment_name"][0], "efs"])
  encrypted      = "true"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "efs"])
  }
}

#mount targets for the private subnets
resource "aws_efs_mount_target" "rundeck-efs-mount" {
  count           = length(var.environment_configuration["subnets_private"])
  file_system_id  = aws_efs_file_system.rundeck-efs.id
  subnet_id       = var.environment_configuration["subnets_private"][count.index]
  security_groups = [aws_security_group.rundeck-efs-sg.id]
}

resource "aws_efs_file_system_policy" "rundeck-efs-policy" {
  depends_on = [
    aws_iam_role.rundeck-ecs-role,
    aws_ecs_service.rundeck-ecs-service,
    aws_efs_file_system.rundeck-efs
  ]
  file_system_id = aws_efs_file_system.rundeck-efs.id
  policy         = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "rundeck-efs-policy",
    "Statement": [
        {
            "Sid": "efs-statement-enforce-secure-transport",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "*",
            "Resource": "${aws_efs_file_system.rundeck-efs.arn}",
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        },
        {
            "Sid": "efs-statement-role-policy",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${aws_iam_role.rundeck-ecs-role.arn}"
            },
            "Action": [
                "elasticfilesystem:ClientRootAccess",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientMount"
            ],
            "Resource": "${aws_efs_file_system.rundeck-efs.arn}"
        }
    ]
}
POLICY
}

#####################
#RDS - Postgres
#####################
#Postgres instance
resource "aws_db_instance" "rundeck-rds-postgres" {
  allocated_storage                   = var.rds_configuration["storage_size"]
  engine                              = "postgres"
  engine_version                      = "11.12"
  identifier                          = join("-", [var.project, var.environment_configuration["environment_name"][0], "rds-postgres"])
  instance_class                      = "db.t3.small"
  vpc_security_group_ids              = [aws_security_group.rundeck-db-sg.id]
  password                            = var.rds_configuration["db_password"]
  username                            = var.rds_configuration["db_username"]
  name                                = var.rds_configuration["db_name"]
  multi_az                            = "true"
  skip_final_snapshot                 = "true"
  db_subnet_group_name                = aws_db_subnet_group.rundeck-rds-subnet-group.id
  apply_immediately                   = true
  iam_database_authentication_enabled = true

  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "rds-postgres"])
  }
}

#db subnet group
resource "aws_db_subnet_group" "rundeck-rds-subnet-group" {
  name       = join("-", [var.project, var.environment_configuration["environment_name"][0], "rds-postgres-subnet-group"])
  subnet_ids = var.environment_configuration["subnets_private"]
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "rds-postgres-subnet-group"])
  }
}

#####################
#ECS Cluster
#####################

#ecs fargate cluster
resource "aws_ecs_cluster" "rundeck-ecs-fargate-cluster" {
  name               = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-fargate-cluster"])
  capacity_providers = ["FARGATE"]
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-fargate-cluster"])
  }
}

#ecs task definition - pinned to dockerhub rundeck at 3.4.2
resource "aws_ecs_task_definition" "rundeck-ecs-task-definition" {
  family                   = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-task-definition"])
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_configuration["service_cpu"]
  memory                   = var.ecs_configuration["service_memory"]
  task_role_arn            = resource.aws_iam_role.rundeck-ecs-role.arn
  execution_role_arn       = resource.aws_iam_role.rundeck-ecs-role.arn

  container_definitions = jsonencode([
    {
      name      = "rundeck-adfs-sso"
      image     = var.ecs_configuration["docker_repo_image"]
      essential = true
      repositoryCredentials = {
        credentialsParameter = "${aws_secretsmanager_secret.rundeck-secret-docker-credentials.arn}"
      }

      portMappings = [
        {
          containerPort = 80
          hostPort      = 80 #unnecessary for Fargate/AWSVPC...
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "RUNDECK_SERVER_FORWARDED"
          value = "true"
        },
        {
          name  = "RUNDECK_GRAILS_URL"
          value = "https://${var.environment_configuration["domain_name"][0]}"
        },
        {
          name  = "RUNDECK_DATABASE_DRIVER"
          value = "org.postgresql.Driver"
        },
        {
          name  = "RUNDECK_DATABASE_URL"
          value = "jdbc:postgresql://${aws_db_instance.rundeck-rds-postgres.endpoint}/${var.rds_configuration["db_name"]}"
        },
        {
          name  = "RUNDECK_DATABASE_USERNAME"
          value = "${var.rds_configuration["db_username"]}"
        },
        {
          name  = "RUNDECK_DATABASE_PASSWORD"
          value = "${var.rds_configuration["db_password"]}"
        },
        {
          name  = "RUNDECK_STORAGE_CONVERTER_1_CONFIG_PASSWORD"
          value = "${var.environment_configuration["rundeck_storage_converter_password"][0]}"
        },
        {
          name  = "RUNDECK_CONFIG_STORAGE_CONVERTER_1_CONFIG_PASSWORD"
          value = "${var.environment_configuration["rundeck_storage_converter_password"][0]}"
        },
        {
          name  = "RUNDECK_PREAUTH_ENABLED"
          value = "true"
        },
        {
          name  = "RUNDECK_PREAUTH_USERSYNC_ENABLED"
          value = "true"
        },
        {
          name  = "RUNDECK_PREAUTH_USERSYNC_EMAIL"
          value = "X-Forwarded-User-Email"
        },
        {
          name  = "RUNDECK_PREAUTH_DELIMITER"
          value = ","
        },
        {
          name  = "RUNDECK_PREAUTH_USERNAME_HEADER"
          value = "X-Forwarded-Uuid"
        },
        {
          name  = "RUNDECK_PREAUTH_ROLES_HEADER"
          value = "X-Forwarded-Roles"
        },
        {
          name  = "RUNDECK_LOGGING_STRATEGY"
          value = "FILE"
        },
        {
          name  = "RUNDECK_PREAUTH_REDIRECT_LOGOUT"
          value = "true"
        },
        {
          name  = "RUNDECK_PREAUTH_REDIRECT_URL"
          value = "/rundecklogout"
        },
        {
          name  = "SSO_PROTECTED_DOMAIN"
          value = "${var.environment_configuration["domain_name"][0]}"
        },
        {
          name  = "SSO_CLIENT_SECRET"
          value = "${var.sso_configuration["client_secret"]}"
        },
        {
          name  = "SSO_CLIENT_ID"
          value = "${var.sso_configuration["client_id"]}"
        },
        {
          name  = "SSO_LOGOUT_URL"
          value = "${var.sso_configuration["logout_url"]}"
        },
        {
          name  = "SSO_AUTH_URL"
          value = "${var.sso_configuration["auth_url"]}"
        },
        {
          name  = "SSO_TOKEN_URL"
          value = "${var.sso_configuration["token_url"]}"
        },
        {
          name  = "SSO_RELYING_PARTY_ID"
          value = "${var.sso_configuration["relying_party_id"]}"
        },
        {
          name  = "VOUCH_DELAY"
          value = "${var.sso_configuration["vouch_delay"]}"
        },
        {
          name  = "SHARED_FILES_PATH"
          value = "${var.ecs_configuration["shared_files_path"]}"
        }
      ]

      readonlyRootFilesystem = false

      mountPoints = [
        {
          "sourceVolume" : "efsroot",
          "containerPath" : "${var.ecs_configuration["shared_files_path"]}/"
        }
      ]
    }
  ])

  volume {
    name = "efsroot"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.rundeck-efs.id
      root_directory     = "/"
      transit_encryption = "ENABLED"
      #transit_encryption_port = 2049
      authorization_config {
        iam = "ENABLED"
      }
    }
  }
}

#ecs service
resource "aws_ecs_service" "rundeck-ecs-service" {
  name                              = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-service"])
  cluster                           = aws_ecs_cluster.rundeck-ecs-fargate-cluster.id
  desired_count                     = 1
  task_definition                   = aws_ecs_task_definition.rundeck-ecs-task-definition.arn
  launch_type                       = "FARGATE"
  enable_execute_command            = var.ecs_configuration["ecs_exec_enabled"]
  health_check_grace_period_seconds = 45
  propagate_tags                    = "SERVICE"

  load_balancer {
    target_group_arn = aws_lb_target_group.rundeck-target-group.arn
    container_name   = "rundeck-adfs-sso"
    container_port   = 80
  }
  network_configuration {
    security_groups  = [aws_security_group.rundeck-mgmt-sg.id]
    subnets          = var.environment_configuration["subnets_private"]
    assign_public_ip = false
  }

  deployment_controller {
    type = "ECS"
  }

  enable_ecs_managed_tags = "true"
  tags = {
    "ecs-service-name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-service"])
  }
}


#####################
#IAM 
#####################

#Standard ECS Task Execution Policy
data "aws_iam_policy" "ecs-task-exec-policy" {
  name = "AmazonECSTaskExecutionRolePolicy"
}

#IAM Role that will be bound to the ECS Service/Task
resource "aws_iam_role" "rundeck-ecs-role" {
  name               = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-iam-role"])
  assume_role_policy = data.aws_iam_policy_document.rundeck-ecs-assume-role-policy.json
  path               = "/"
  inline_policy {
    name   = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-task-role-policy"])
    policy = data.aws_iam_policy_document.rundeck-ecs-task-role-policy.json
  }
  managed_policy_arns = [
    data.aws_iam_policy.ecs-task-exec-policy.arn
  ]

  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-iam-role"])
  }
}

#Assume role policy for ECS, allows a role to be assigned to an ecs service/task
data "aws_iam_policy_document" "rundeck-ecs-assume-role-policy" {
  policy_id = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-assume-role-policy"])
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# #ECS Policy for rundeck allowing EFS connectivity
data "aws_iam_policy_document" "rundeck-ecs-task-role-policy" {
  policy_id = join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-role-policy"])
  statement {
    actions = ["elasticfilesystem:ClientRootAccess",
      "elasticfilesystem:ClientWrite",
    "elasticfilesystem:ClientMount"]
    resources = [
      aws_efs_file_system.rundeck-efs.arn
    ]
  }

  #doing a dynamic statement here to allow for the policy to have ssm privileges if ECS exec is enabled.
  dynamic "statement" {
    for_each = var.ecs_configuration["ecs_exec_enabled"] ? [1] : []
    content {
      actions = ["ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel"]
      resources = ["*"]
    }
  }
}

#####################
#Secrets Manager - for Docker Repo Creds
#####################

#Secrets manager secret to hold docker repo creds
resource "aws_secretsmanager_secret" "rundeck-secret-docker-credentials" {
  name        = join("-", [var.project, var.environment_configuration["environment_name"][0], "secret-docker-creds"])
  description = "This is is a secret for the rundeck task definition ${join("-", [var.project, var.environment_configuration["environment_name"][0], "ecs-task-definition"])}"
  tags = {
    "Name" = join("-", [var.project, var.environment_configuration["environment_name"][0], "secret-docker-creds"])
  }
}

#Secrets manager secret version to set value
resource "aws_secretsmanager_secret_version" "rundeck-secret-docker-credentials-version" {
  secret_id = aws_secretsmanager_secret.rundeck-secret-docker-credentials.id
  secret_string = jsonencode(
    {
      username = var.ecs_configuration["docker_repo_username"]
      password = var.ecs_configuration["docker_repo_password"]
    }
  )
}

#Secrets manager policy to allow ECS Service to retrieve secret
resource "aws_secretsmanager_secret_policy" "rundeck-secret-docker-credentials-policy" {
  secret_arn = aws_secretsmanager_secret.rundeck-secret-docker-credentials.arn

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "rundeckcredentialspolicy",
      "Effect": "Allow",
      "Principal": {
          "AWS": "${aws_iam_role.rundeck-ecs-role.arn}"
      },
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "${aws_secretsmanager_secret.rundeck-secret-docker-credentials.arn}"
    }
  ]
}
POLICY
}