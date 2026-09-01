# HTTP API for machine-to-machine callers (partner webhooks, internal
# batch triggers). Every route is wired to the JWT authorizer; there is
# no route with authorization_type = "NONE" except the health probe,
# which returns static status only.

resource "aws_apigatewayv2_api" "demo" {
  name          = "demo-${var.environment}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://portal.example.invalid"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 3600
  }

  tags = var.tags
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.demo.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "demo-jwt"

  jwt_configuration {
    issuer   = var.auth_issuer
    audience = [var.auth_audience]
  }
}

resource "aws_apigatewayv2_route" "list_notifications" {
  api_id             = aws_apigatewayv2_api.demo.id
  route_key          = "GET /v1/notifications"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
  target             = "integrations/${aws_apigatewayv2_integration.notify.id}"
}

resource "aws_apigatewayv2_route" "create_notification" {
  api_id             = aws_apigatewayv2_api.demo.id
  route_key          = "POST /v1/notifications"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
  target             = "integrations/${aws_apigatewayv2_integration.notify.id}"
}

resource "aws_apigatewayv2_integration" "notify" {
  api_id                 = aws_apigatewayv2_api.demo.id
  integration_type       = "HTTP_PROXY"
  integration_method     = "ANY"
  integration_uri        = "https://notify.internal.example.invalid/{proxy}"
  payload_format_version = "1.0"

  tls_config {
    # Upstream certificate must match this name; TLS verification stays on.
    server_name_to_verify = "notify.internal.example.invalid"
  }
}

resource "aws_apigatewayv2_stage" "live" {
  api_id      = aws_apigatewayv2_api.demo.id
  name        = "live"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 200
    throttling_rate_limit  = 100
  }

  tags = var.tags
}
