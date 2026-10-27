terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "ami_id" {
  type        = string
  description = "AMI for the app server"
}

# A02: a private bucket. Block public access explicitly, even though new buckets
# get these settings by default, so a console change shows up as drift.
resource "aws_s3_bucket" "invoices" {
  bucket_prefix = "invoices-"
}

resource "aws_s3_bucket_public_access_block" "invoices" {
  bucket                  = aws_s3_bucket.invoices.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invoices" {
  bucket = aws_s3_bucket.invoices.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# SSRF defense in depth: require IMDSv2 session tokens, and keep the metadata
# service out of reach of containers on the host (hop limit 1).
resource "aws_instance" "app" {
  ami           = var.ami_id
  instance_type = "t4g.small"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }
}
