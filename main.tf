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
    cidr_blocks = ["0.0.0.0/0"]  # Allow from NLB
  }

  dynamic "ingress" {
    for_each = [for port in range(8192, 8201) : port]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]  # Allow from NLB
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

# Add a Network Load Balancer for the Transfer server
resource "aws_lb" "transfer_nlb" {
  name               = "transfer-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.public.id]

  enable_cross_zone_load_balancing = true
}

# Add listener for the NLB
resource "aws_lb_listener" "ftps_listener" {
  load_balancer_arn = aws_lb.transfer_nlb.arn
  port              = 21
  protocol          = "TLS"
  certificate_arn   = trimspace(data.local_file.cert_arn.content)

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.transfer_tg.arn
  }
}

# Add passive port listeners (for FTPS data connections)
resource "aws_lb_listener" "ftps_passive_listeners" {
  count             = 9
  load_balancer_arn = aws_lb.transfer_nlb.arn
  port              = 8192 + count.index
  protocol          = "TLS"
  certificate_arn   = trimspace(data.local_file.cert_arn.content)

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.transfer_passive_tg[count.index].arn
  }
}

# Create target groups for the Transfer server
resource "aws_lb_target_group" "transfer_tg" {
  name     = "transfer-tg"
  port     = 21
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id

  health_check {
    protocol = "TCP"
    port     = 21
  }
}

# Create target groups for passive ports
resource "aws_lb_target_group" "transfer_passive_tg" {
  count    = 9
  name     = "transfer-passive-tg-${8192 + count.index}"
  port     = 8192 + count.index
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id

  health_check {
    protocol = "TCP"
    port     = 8192 + count.index
  }
}

# Modify the Transfer server configuration
resource "aws_transfer_server" "ftps_server" {
  endpoint_type          = "VPC"
  protocols              = ["FTPS"]
  identity_provider_type = "AWS_LAMBDA"
  function               = aws_lambda_function.transfer_auth_lambda.arn
  certificate            = trimspace(data.local_file.cert_arn.content)
  
  protocol_details {
    passive_ip = aws_lb.transfer_nlb.dns_name  # Use NLB DNS name as passive IP
    }
  }

  endpoint_details {
    vpc_id             = aws_vpc.main.id
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.transfer_sg.id]
    address_allocation_ids = []  # Required for VPC_ENDPOINT type
  }

  tags = {
    Name = "FTPS-Server"
  }
}

# Target group attachments for the Transfer server
resource "aws_lb_target_group_attachment" "transfer_tg_attachment" {
  target_group_arn = aws_lb_target_group.transfer_tg.arn
  target_id        = aws_transfer_server.ftps_server.id
  port             = 21
}

resource "aws_lb_target_group_attachment" "transfer_passive_tg_attachment" {
  count            = 9
  target_group_arn = aws_lb_target_group.transfer_passive_tg[count.index].arn
  target_id        = aws_transfer_server.ftps_server.id
  port             = 8192 + count.index
}

# Update security group to allow traffic from the NLB to the Transfer server
resource "aws_security_group_rule" "transfer_from_nlb" {
  type              = "ingress"
  from_port         = 21
  to_port           = 21
  protocol          = "tcp"
  security_group_id = aws_security_group.transfer_sg.id
  source_security_group_id = aws_security_group.nlb_sg.id
}

# Create a security group for the NLB
resource "aws_security_group" "nlb_sg" {
  name        = "nlb-sg"
  description = "Security group for the NLB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = [for port in range(8192, 8201) : port]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create VPC endpoint for Transfer server
resource "aws_vpc_endpoint" "transfer_endpoint" {
  vpc_id              = aws_vpc.main.id
  service_name        = aws_vpc_endpoint_service.transfer_endpoint_service.service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.transfer_sg.id]
  private_dns_enabled = false
}

# Register the Transfer server VPC endpoint with NLB target groups
resource "aws_vpc_endpoint_service" "transfer_endpoint_service" {
  acceptance_required        = false
  network_load_balancer_arns = [aws_lb.transfer_nlb.arn]
}

# Add a private hosted zone for the custom domain
resource "aws_route53_zone" "private_zone" {
  name = "example.com"
  
  vpc {
    vpc_id = aws_vpc.main.id
  }
}

# Add a record in the private hosted zone
resource "aws_route53_record" "transfer_private_record" {
  zone_id = aws_route53_zone.private_zone.zone_id
  name    = "transfer.example.com"
  type    = "CNAME"
  ttl     = 300
  records = [aws_lb.transfer_nlb.dns_name]
}

# Add a public hosted zone if needed
resource "aws_route53_zone" "public_zone" {
  name = "example.com"
}

# Add a record in the public hosted zone
resource "aws_route53_record" "transfer_public_record" {
  zone_id = aws_route53_zone.public_zone.zone_id
  name    = "transfer.example.com"
  type    = "A"
  
  alias {
    name                   = aws_lb.transfer_nlb.dns_name
    zone_id                = aws_lb.transfer_nlb.zone_id
    evaluate_target_health = true
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

# S3 bucket for FTPS storage - with a more unique name in us-east-1
resource "aws_s3_bucket" "ftps_bucket" {
  bucket = "ftps-transfer-bucket-${data.aws_caller_identity.current.account_id}"  # More unique name
  # No need for provider specification since we're using us-east-1 as the main region
}

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
    mkdir c:\temp
    cd c:\temp
    curl -LO https://cdn.winscp.net/files/WinSCP-6.3.7-Setup.exe?secure=jGMLrV3pq9qv-RgLRgy79Q==,1742292820
    </script>
  EOT

  tags = {
    Name = "WinSCP-Client"
  }
}

# Output the hostname and endpoint
output "transfer_hostname" {
  value = aws_transfer_server.ftps_server.hostname
}

output "transfer_endpoint" {
  value = aws_lb.transfer_nlb.dns_name
}

output "transfer_endpoint_service" {
  value = aws_vpc_endpoint_service.transfer_endpoint_service.service_name
}
