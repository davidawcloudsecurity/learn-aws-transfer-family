provider "aws" {
  region = "us-east-1"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block = "192.168.0.0/16"
}

# Public Subnet for Windows EC2
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "192.168.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

# Private Subnet for Transfer Server
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "192.168.2.0/24"
  availability_zone = "us-east-1a"
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

# Route Table for Public Subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

# Associate Public Subnet with Route Table
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group for Transfer Server
resource "aws_security_group" "transfer_sg" {
  name        = "transfer-sg"
  description = "Allow FTPS traffic from NLB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  dynamic "ingress" {
    for_each = [for port in range(8192, 8201) : port]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [aws_subnet.private.cidr_block]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role for the Lambda function
resource "aws_iam_role" "transfer_lambda_role" {
  name = "transfer-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.transfer_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function for custom authentication
resource "aws_lambda_function" "transfer_auth_lambda" {
  filename      = "transfer_auth_lambda.zip" # You'll need to create this zip with the Lambda code
  function_name = "transfer-auth-handler"
  role          = aws_iam_role.transfer_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 30

  # Add environment variables if needed
  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

# Transfer Server with custom identity provider
resource "aws_transfer_server" "ftps_server" {
  endpoint_type         = "VPC"
  protocols             = ["FTPS"]
  identity_provider_type = "AWS_LAMBDA"
  function              = aws_lambda_function.transfer_auth_lambda.arn

  protocol_details {
    passive_ip = "0.0.0.0"
  }

  endpoint_details {
    vpc_id             = aws_vpc.main.id
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.transfer_sg.id]
  }
}

# IAM Role for Transfer users
resource "aws_iam_role" "transfer_user_role" {
  name = "transfer-user-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "transfer.amazonaws.com"
        }
      }
    ]
  })
}

# Policy for Transfer users to access S3
resource "aws_iam_policy" "transfer_user_policy" {
  name        = "transfer-user-policy"
  description = "Allow Transfer users to access S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::ftps-bucket"
      },
      {
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::ftps-bucket/*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "transfer_user_policy_attach" {
  role       = aws_iam_role.transfer_user_role.name
  policy_arn = aws_iam_policy.transfer_user_policy.arn
}

# S3 bucket for FTPS storage
resource "aws_s3_bucket" "ftps_bucket" {
  bucket = "ftps-bucket"
}

# ... [Keep existing NLB, Target Groups, and Listeners configuration from original code] ...

# Security Group for Windows EC2 Instance
resource "aws_security_group" "windows_sg" {
  name        = "windows-sg"
  description = "Allow RDP and FTPS access"
  vpc_id      = aws_vpc.main.id

  # Allow RDP from your IP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  # Allow outbound to NLB
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  egress {
    from_port   = 8192
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role for SSM
resource "aws_iam_role" "ec2_ssm_role" {
  name = "EC2SSMTransferRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach SSM Managed Policy
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "EC2TransferInstanceProfile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Windows EC2 Instance
resource "aws_instance" "windows" {
  ami                  = "ami-001adaa5c3ee02e10"
  instance_type        = "t3.medium"
  subnet_id            = aws_subnet.public.id
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids = [aws_security_group.windows_sg.id]

  # Fixed user_data with heredoc syntax
  user_data = <<-EOT
    <powershell>
    # Download WinSCP
    $winscpPath = "$env:USERPROFILE\Downloads\WinSCP-6.3.7-Setup.exe"
    Invoke-WebRequest -Uri "https://winscp.net/download/WinSCP-6.3.7-Setup.exe" -OutFile $winscpPath

    # Install WinSCP silently
    Start-Process -FilePath $winscpPath -ArgumentList "/VERYSILENT /ALLUSERS" -Wait

    # Optional: Clean up installer
    Remove-Item -Path $winscpPath -Force

    # Enable ICMP for troubleshooting (optional)
    New-NetFirewallRule -DisplayName "Allow ICMPv4" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Action Allow
    </powershell>
    <script>
    net users admin2 P@ssw0rd123 /add
    net localgroup Administrators admin2 /add
    </script>
  EOT

  tags = {
    Name = "WinSCP-Client"
  }
}
