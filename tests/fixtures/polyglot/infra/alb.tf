# Public application load balancer for the portal edge.
# Security posture: HTTPS only. The security group admits 443 and
# nothing else; there is no port-80 listener to downgrade to.

resource "aws_security_group" "alb" {
  name        = "demo-${var.environment}-alb"
  description = "ALB ingress: TLS only"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Forward to service targets inside the VPC only"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["10.32.0.0/16"]
  }

  tags = var.tags
}

resource "aws_lb" "edge" {
  name               = "demo-${var.environment}-edge"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
  enable_deletion_protection = true

  tags = var.tags
}

resource "aws_lb_target_group" "portal_bff" {
  name        = "demo-${var.environment}-portal"
  port        = 8443
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled  = true
    path     = "/healthz"
    protocol = "HTTPS"
    matcher  = "200"
    interval = 15
  }

  tags = var.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.edge.arn
  port              = 443
  protocol          = "HTTPS"
  # Modern TLS policy: TLS 1.3 with a 1.2 floor, forward secrecy only.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn = var.alb_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal_bff.arn
  }
}
