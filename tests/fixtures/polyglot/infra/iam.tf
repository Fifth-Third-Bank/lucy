# Task-role IAM for the batch worker. Deliberately narrow:
#   - reads/writes ONE prefix in ONE bucket
#   - reads SSM parameters under ONE path
#   - no wildcards on actions or resources, no iam:* anywhere

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "task_assume" {
  statement {
    sid     = "EcsTasksAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "batch_worker" {
  name               = "demo-${var.environment}-batch-worker"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "batch_worker" {
  statement {
    sid    = "SettlementArtifactsReadWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${var.artifact_bucket_name}/settlement/${var.environment}/*",
    ]
  }

  statement {
    sid       = "SettlementArtifactsList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.artifact_bucket_name}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["settlement/${var.environment}/*"]
    }
  }

  statement {
    sid     = "ScopedParameterRead"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParametersByPath"]
    resources = [
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter${var.parameter_path_prefix}/*",
    ]
  }

  statement {
    sid       = "DecryptWithAppKeyOnly"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.app_secrets.arn]
  }
}

resource "aws_iam_role_policy" "batch_worker" {
  name   = "demo-${var.environment}-batch-worker"
  role   = aws_iam_role.batch_worker.id
  policy = data.aws_iam_policy_document.batch_worker.json
}

resource "aws_kms_key" "app_secrets" {
  description             = "Envelope key for demo app secrets (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}
