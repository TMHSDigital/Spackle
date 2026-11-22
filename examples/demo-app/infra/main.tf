terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "attachments" {
  bucket = "fixture-notes-attachments"
}

resource "aws_s3_bucket_acl" "attachments" {
  bucket = aws_s3_bucket.attachments.id
  acl    = "public-read"
}

resource "aws_security_group" "notes" {
  name        = "notes-app"
  description = "notes demo instance"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
