# Shared input variables for the fixture estate's infrastructure layer.
# No defaults contain real account ids, hostnames, or secrets.

variable "environment" {
  description = "Deployment environment name (fixture estates use 'fixture')."
  type        = string
  default     = "fixture"

  validation {
    condition     = contains(["fixture", "dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: fixture, dev, staging, prod."
  }
}

variable "vpc_id" {
  description = "VPC that hosts the public ALB and private services."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the ALB (at least two AZs)."
  type        = list(string)
}

variable "alb_certificate_arn" {
  description = "ACM certificate ARN for the public listener."
  type        = string
}

variable "auth_issuer" {
  description = "OIDC issuer that mints tokens for the API Gateway authorizer."
  type        = string
  default     = "https://auth.example.invalid/realms/demo"
}

variable "auth_audience" {
  description = "Audience the JWT authorizer requires on every token."
  type        = string
  default     = "demo-edge"
}

variable "artifact_bucket_name" {
  description = "S3 bucket holding demo batch artifacts."
  type        = string
  default     = "demo-fixture-artifacts"
}

variable "parameter_path_prefix" {
  description = "SSM parameter path the services may read from (scoped IAM)."
  type        = string
  default     = "/demo/fixture"
}

variable "tags" {
  description = "Common resource tags."
  type        = map(string)
  default = {
    project = "demo-fixture-estate"
    owner   = "dev@example.invalid"
  }
}
