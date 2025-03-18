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
  description = "Allow FTPS traffic from Windows EC2"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 21
    to_port         = 21
    protocol        = "tcp"
    security_groups = [aws_security_group.windows_sg.id]
  }

  dynamic "ingress" {
    for_each = [for port in range(8192, 8201) : port]
    content {
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [aws_security_group.windows_sg.id]
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

# Create a local file with the Lambda code
resource "local_file" "lambda_source" {
  content  = <<-EOT
    // AWS Lambda function for custom identity provider with username/password auth
    exports.handler = async (event) => {
      console.log("Authentication event:", JSON.stringify(event));
      
      // Sample user configurations - in production, store these in a database or AWS Secrets Manager
      const users = {
        "testuser": {
          Password: "StrongPassword123!",
          Role: "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/transfer-user-role",
          HomeDirectory: "/ftps-bucket/testuser",
          // Optional: For virtual folders
          HomeDirectoryType: "LOGICAL",
          HomeDirectoryMappings: [
            {
              Entry: "/",
              Target: "/ftps-bucket/testuser"
            }
          ]
        }
      };
      
      // Extract the provided credentials
      const username = event.username;
      const password = event.password;
      
      console.log(`Authenticating user: $${username}`);
      
      // Check if user exists and password matches
      if (users[username] && users[username].Password === password) {
        console.log("Authentication successful");
        
        // Return the successful response with user configuration
        return {
          Role: users[username].Role,
          HomeDirectory: users[username].HomeDirectory,
          HomeDirectoryType: users[username].HomeDirectoryType,
          HomeDirectoryMappings: users[username].HomeDirectoryMappings
        };
      }
      
      // Authentication failed
      console.log("Authentication failed");
      return {
        Message: "Authentication failed"
      };
    };
  EOT
  filename = "${path.module}/lambda/index.js"
}

# Data source to get the current AWS account ID
data "aws_caller_identity" "current" {}

# Null resource to create the ZIP file
resource "null_resource" "lambda_zip" {
  depends_on = [local_file.lambda_source]

  provisioner "local-exec" {
    command = "cd ${path.module}/lambda && zip -r ../transfer_auth_lambda.zip index.js"
  }

  # Trigger recreation whenever the source file changes
  triggers = {
    source_code_hash = local_file.lambda_source.content_base64sha256
  }
}

# Data source for the ZIP file
data "archive_file" "lambda_zip_data" {
  depends_on  = [null_resource.lambda_zip]
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/transfer_auth_lambda.zip"
}

# Lambda permission for Transfer service
resource "aws_lambda_permission" "transfer_invoke_lambda" {
  statement_id  = "AllowTransferInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.transfer_auth_lambda.function_name
  principal     = "transfer.amazonaws.com"
  source_arn    = aws_transfer_server.ftps_server.arn
}

# Lambda function using the dynamically created ZIP
resource "aws_lambda_function" "transfer_auth_lambda" {
  filename         = data.archive_file.lambda_zip_data.output_path
  function_name    = "transfer-auth-handler"
  role             = aws_iam_role.transfer_lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  timeout          = 30
  source_code_hash = data.archive_file.lambda_zip_data.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

# Create a directory for the certificate
resource "null_resource" "create_cert_directory" {
  provisioner "local-exec" {
    command = "mkdir -p ${path.module}/certs"
  }
}

# Generate a self-signed certificate using OpenSSL
resource "null_resource" "generate_self_signed_cert" {
  depends_on = [null_resource.create_cert_directory]

  provisioner "local-exec" {
    command = <<-EOT
      openssl req -x509 -newkey rsa:2048 -keyout ${path.module}/certs/private.key -out ${path.module}/certs/certificate.pem -days 365 -nodes -subj "/CN=transfer.example.com" -addext "subjectAltName=DNS:transfer.example.com"
    EOT
  }

  # Trigger recreation if the certificate needs to be regenerated
  triggers = {
    always_run = "${timestamp()}"  # Use with caution: will regenerate on every apply
  }
}

# Import the certificate into ACM
resource "null_resource" "import_cert_to_acm" {
  depends_on = [null_resource.generate_self_signed_cert]

  provisioner "local-exec" {
    command = <<-EOT
      CERT_ARN=$(aws acm import-certificate \
        --certificate fileb://${path.module}/certs/certificate.pem \
        --private-key fileb://${path.module}/certs/private.key \
        --region us-east-1 \
        --output text \
        --query 'CertificateArn')
      echo $CERT_ARN > ${path.module}/certs/cert_arn.txt
    EOT
  }
}

# Read the certificate ARN from the file
data "local_file" "cert_arn" {
  depends_on = [null_resource.import_cert_to_acm]
  filename   = "${path.module}/certs/cert_arn.txt"
}

# Transfer Server with custom identity provider
resource "aws_transfer_server" "ftps_server" {
  endpoint_type         = "VPC"
  protocols             = ["FTPS"]
  identity_provider_type = "AWS_LAMBDA"
  function              = aws_lambda_function.transfer_auth_lambda.arn
  certificate           = trimspace(data.local_file.cert_arn.content)

  protocol_details {
    passive_ip = local.nlb_private_ip
  }

  endpoint_details {
    vpc_id             = aws_vpc.main.id
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.transfer_sg.id]
  }

  depends_on = [aws_lb.nlb]  # Ensure NLB is created first
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

# S3 bucket for FTPS storage - with a more unique name in us-east-1
resource "aws_s3_bucket" "ftps_bucket" {
  bucket = "ftps-transfer-bucket-${data.aws_caller_identity.current.account_id}"  # More unique name
  # No need for provider specification since we're using us-east-1 as the main region
}

resource "aws_lb" "nlb" {
  name               = "ftps-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.private.id]
}

data "aws_network_interfaces" "nlb_enis" {
  depends_on = [aws_lb.nlb]
  filter {
    name   = "description"
    values = ["ELB net/${aws_lb.nlb.name}/*"]
  }
  filter {
    name   = "vpc-id"
    values = [aws_vpc.main.id]
  }
}

data "aws_network_interface" "nlb_eni" {
  id = data.aws_network_interfaces.nlb_enis.ids[0]
}

locals {
  nlb_private_ip = data.aws_network_interface.nlb_eni.private_ip
}

data "aws_vpc_endpoint" "transfer_endpoint" {
  id = aws_transfer_server.ftps_server.endpoint_details[0].vpc_endpoint_id
}

data "aws_network_interface" "transfer_eni" {
  id = data.aws_vpc_endpoint.transfer_endpoint.network_interface_ids[0]
}

locals {
  transfer_eni_ip = data.aws_network_interface.transfer_eni.private_ip
}

resource "aws_lb_target_group" "control" {
  name        = "ftps-control-tg"
  port        = 21
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb_target_group_attachment" "control_attach" {
  target_group_arn = aws_lb_target_group.control.arn
  target_id        = local.transfer_eni_ip
  port             = 21
}

resource "aws_lb_target_group" "passive" {
  for_each = toset([for port in range(8192, 8202) : tostring(port)])  # 8192 to 8201 inclusive
  name        = "ftps-passive-${each.key}-tg"
  port        = each.key
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id
}

resource "aws_lb_target_group_attachment" "passive_attach" {
  for_each         = aws_lb_target_group.passive
  target_group_arn = each.value.arn
  target_id        = local.transfer_eni_ip
  port             = tonumber(each.key)
}

resource "aws_lb_listener" "control_listener" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control.arn
  }
}

resource "aws_lb_listener" "passive_listeners" {
  for_each          = aws_lb_target_group.passive
  load_balancer_arn = aws_lb.nlb.arn
  port              = each.key
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = each.value.arn
  }
}

# Security Group for Windows EC2 Instance
resource "aws_security_group" "windows_sg" {
  name        = "windows-sg"
  description = "Allow RDP and FTPS access"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  egress {
    from_port   = 8192
    to_port     = 8201  # Corrected to match 8192-8201 range
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
    mkdir c:\temp
    cd c:\temp
    curl -LO https://cdn.winscp.net/files/WinSCP-6.3.7-Setup.exe?secure=yiG28rtqKcUdG1Q0Dc6WyQ==,1742122915
    </script>
  EOT

  tags = {
    Name = "WinSCP-Client"
  }
}

output "nlb_dns_name" {
  value = aws_lb.nlb.dns_name
}
