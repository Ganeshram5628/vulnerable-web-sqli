# Vulnerable Terraform sample to trigger tfsec-fallback regex rules

provider "aws" {
  region = "us-east-1"
}

# Security group that allows public access from anywhere (0.0.0.0/0)
resource "aws_security_group" "bad_sg" {
  name        = "bad_sg"
  description = "Security group allowing public access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]    # <-- Public Access Detection (MEDIUM)
  }
}

# Example of a hardcoded password and API key (should trigger Hardcoded Secrets Detection)
resource "aws_db_instance" "bad_db" {
  identifier         = "bad-db"
  allocated_storage  = 20
  engine             = "mysql"
  instance_class     = "db.t3.micro"
  username           = "admin"
  password           = "mypassword123"   # <-- Hardcoded secret (HIGH)
  skip_final_snapshot = true
}

# Another sensitive variable assignment example that triggers the same regex
variable "some_api_key" {
  default = "sk-1234567890"   # <-- Hardcoded secret (HIGH)
}