# Cloud Storage & Infrastructure Configuration
resource "aws_s3_bucket" "customer_exports" {
  bucket = "corp-customer-kyc-exports-prod"
  acl    = "public-read"
}

variable "azure_blob_connection" {
  default = "DefaultEndpointsProtocol=https;AccountName=corpprodblobs;AccountKey=mK8vQ2pL9xR4tY7wZ1nB5vC3xZ8lK4jH6gF2dS9aP0oI8uY7tR6eW5qA==;EndpointSuffix=core.windows.net"
}

variable "gcp_bucket_api_key" {
  default = "AIzaSyD9876543210abcdefghijklmnopqrstuvwx"
}
