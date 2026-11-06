import re
from typing import Dict, Any, List

COMMON_PLACEHOLDERS = {
    "your_api_key", "my_secret_key", "insert_token_here", "dummy_token",
    "example_key", "your_password", "changeme", "admin123", "placeholder",
    "todo_add_key", "xxxxxxxx", "00000000", "12345678", "your_aws_key",
    "replace_me", "none", "null", "true", "false", "localhost", "example.com"
}

SUSPICIOUS_VARIABLE_NAMES = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "access_token", "auth_token", "private_key", "client_secret",
    "database_url", "db_pass", "connection_string", "encryption_key",
    "signing_key", "webhook_secret", "master_key", "storage_key"
]

BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "id": "LS-AWS-001",
        "name": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "vector": "Cloud & Config",
        "severity": "Critical",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "min_entropy": 2.8,
        "confidence": 95,
        "description": "20-character AWS IAM Access Key identifier exposed in source, config, or logs.",
        "remediation": "Deactivate key in AWS IAM Console immediately, review CloudTrail logs for unauthorized API calls, and migrate to IAM Roles.",
        "fp_guidance": "Verify if the key ends with EXAMPLE (AWS documentation sample key)."
    },
    {
        "id": "LS-AWS-002",
        "name": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "vector": "Cloud & Config",
        "severity": "Critical",
        "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "min_entropy": 4.2,
        "confidence": 94,
        "description": "40-character base64 AWS Secret Access Key paired with IAM credentials.",
        "remediation": "Rotate IAM access key pair immediately and store secrets in AWS Secrets Manager or Parameter Store.",
        "fp_guidance": "Check if value is a 40-character Git commit SHA hash."
    },
    {
        "id": "LS-GH-002",
        "name": "GitHub Personal Access Token",
        "category": "API Tokens",
        "vector": "Repositories & CI/CD",
        "severity": "Critical",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}",
        "min_entropy": 3.8,
        "confidence": 98,
        "description": "GitHub classic or fine-grained Personal Access Token granting repository access.",
        "remediation": "Revoke token in GitHub Developer Settings, audit repository security logs, and switch to short-lived GitHub App tokens.",
        "fp_guidance": "Low false-positive rate due to strict ghp_/github_pat_ prefix."
    },
    {
        "id": "LS-KEY-003",
        "name": "Private SSH / Cryptographic Key",
        "category": "Cryptographic Keys",
        "vector": "Repositories & Config",
        "severity": "Critical",
        "pattern": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED)? ?PRIVATE KEY-----",
        "min_entropy": 0.0,
        "confidence": 100,
        "description": "PEM/OpenSSH private cryptographic key header exposed directly in file content.",
        "remediation": "Purge file from Git history using git-filter-repo, revoke authorized_keys or TLS certificates, and generate a new keypair.",
        "fp_guidance": "Test fixtures in unit tests may trigger this; never reuse test keys in production."
    },
    {
        "id": "LS-DB-004",
        "name": "Database Connection String URI",
        "category": "Database Credentials",
        "vector": "Config & Logs",
        "severity": "High",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql)://[a-zA-Z0-9_\-\.]+:[^@\s/'\"]{3,}@[a-zA-Z0-9\-\.]+(?::[0-9]+)?/[a-zA-Z0-9_\-\.?=&]+",
        "min_entropy": 2.5,
        "confidence": 92,
        "description": "Database connection URI containing embedded plaintext username and password.",
        "remediation": "Rotate database user password, restrict network access to private VPC subnets, and inject credentials via environment variables.",
        "fp_guidance": "Localhost development URIs (e.g. @localhost:5432) have lower impact but should still use env vars."
    },
    {
        "id": "LS-JWT-005",
        "name": "JSON Web Token (JWT) / Bearer Token",
        "category": "Authentication Tokens",
        "vector": "Application Logs",
        "severity": "Medium",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "min_entropy": 3.9,
        "confidence": 85,
        "description": "Base64url-encoded JSON Web Token exposed in application logs or configuration.",
        "remediation": "Sanitize Authorization headers in logging middleware, invalidate active session tokens, and verify short token TTLs.",
        "fp_guidance": "Check decoded payload exp claim to determine if the token is already expired."
    },
    {
        "id": "LS-CLOUD-007",
        "name": "Azure Storage Connection String / SAS Token",
        "category": "Cloud Storage",
        "vector": "Cloud Storage",
        "severity": "Critical",
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[a-zA-Z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,88}|sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&\s]+&sig=[A-Za-z0-9%+/=]{20,}",
        "min_entropy": 3.5,
        "confidence": 96,
        "description": "Azure Blob/Queue/Table Storage account key or Shared Access Signature (SAS) URL.",
        "remediation": "Regenerate Storage Account keys in Azure Portal, revoke compromised SAS policies, and adopt Azure Managed Identities.",
        "fp_guidance": "Emulator strings (UseDevelopmentStorage=true) are safe."
    },
    {
        "id": "LS-CLOUD-008",
        "name": "AWS S3 Pre-signed URL or Public Bucket ACL",
        "category": "Cloud Storage",
        "vector": "Cloud Storage",
        "severity": "High",
        "pattern": r"https?://[a-z0-9\.\-]+s3[a-z0-9\.\-]*\.amazonaws\.com/[^\s'\"]+X-Amz-Signature=[a-f0-9]{64}|(?i)(?:acl\s*=\s*['\"]public-read(?:-write)?['\"]|\"Principal\"\s*:\s*\"\*\"\s*,\s*\"Effect\"\s*:\s*\"Allow\")",
        "min_entropy": 2.5,
        "confidence": 88,
        "description": "Exposed S3 pre-signed download/upload URL or Terraform/IAM public bucket policy.",
        "remediation": "Enable S3 Block Public Access at the account level, remove wildcard (*) principals, and shorten pre-signed URL expiration.",
        "fp_guidance": "Verify if the bucket is intentionally hosting static public web assets."
    },
    {
        "id": "LS-CLOUD-009",
        "name": "Google Cloud (GCP) API Key & Service Account",
        "category": "Cloud Credentials",
        "vector": "Cloud Storage",
        "severity": "Critical",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}|\"type\"\s*:\s*\"service_account\"",
        "min_entropy": 2.5,
        "confidence": 93,
        "description": "Google Cloud Platform API key or Service Account JSON credential file.",
        "remediation": "Delete the service account key in GCP IAM console, restrict API key by HTTP referrer/IP, and use Workload Identity Federation.",
        "fp_guidance": "Firebase web API keys (AIza...) still require strict Firestore Security Rules verification."
    },
    {
        "id": "LS-OAUTH-010",
        "name": "OAuth Client Secret / Slack / Stripe API Key",
        "category": "OAuth & API Keys",
        "vector": "Repositories & Config",
        "severity": "Critical",
        "pattern": r"(?:sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}|(?i)client_secret\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.~]{16,64})['\"])",
        "min_entropy": 3.5,
        "confidence": 92,
        "description": "Production payment gateway key (Stripe), Slack bot token, or OAuth 2.0 client secret.",
        "remediation": "Roll the secret key in the provider dashboard immediately and inspect webhook/API access logs.",
        "fp_guidance": "Stripe sk_test_ keys are sandbox keys and lower severity than sk_live_."
    },
    {
        "id": "LS-LOG-011",
        "name": "Credential Leaked in Application Log / URL",
        "category": "Log Exposure",
        "vector": "Application Logs",
        "severity": "High",
        "pattern": r"(?i)(?:[?&](?:api_key|apikey|access_token|password|secret|token)=([a-zA-Z0-9_\-\.%]{10,128})|Authorization:\s*(?:Basic|Bearer)\s+([a-zA-Z0-9_\-\.=]{12,512}))",
        "min_entropy": 3.3,
        "confidence": 86,
        "description": "Sensitive authentication header or query parameter written into application or access logs.",
        "remediation": "Configure log redaction filters in your logging framework, stop passing secrets in URL query parameters, and purge affected log archives.",
        "fp_guidance": "Redacted log lines (containing ***) are automatically ignored."
    },
    {
        "id": "LS-GEN-006",
        "name": "Context-Aware Hardcoded Password / Secret",
        "category": "Hardcoded Passwords",
        "vector": "Config & Code",
        "severity": "High",
        "pattern": r"(?i)(?:password|passwd|pwd|secret|api_key|apikey|access_token|private_key|client_secret|auth_token|database_url)\s*[:=]\s*['\"]([^'\"]{8,120})['\"]",
        "min_entropy": 3.4,
        "confidence": 80,
        "description": "Suspicious credential variable assigned to a high-entropy string literal.",
        "remediation": "Extract hardcoded literal into an environment variable or secret vault and rotate the exposed credential.",
        "fp_guidance": "Ensure variable is not referencing an environment lookup like os.getenv()."
    },
    {
        "id": "LS-ENV-012",
        "name": "High-Entropy Sensitive Environment Assignment",
        "category": "Sensitive Env Vars",
        "vector": "Config & Code",
        "severity": "Medium",
        "pattern": r"^[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASS|PWD|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*['\"]?([A-Za-z0-9+/=_\-\.!@#$\%^&*]{16,128})['\"]?$",
        "min_entropy": 4.1,
        "confidence": 78,
        "description": "Environment configuration assignment containing a high-randomness secret value.",
        "remediation": "Add .env files to .gitignore, provide only redacted .env.example templates in git, and inject production secrets at runtime.",
        "fp_guidance": "Public keys or non-secret UUIDs can be marked as False Positive."
    }
]

def is_placeholder(val: str) -> bool:
    clean = val.lower().strip().strip("'\"`")
    if clean in COMMON_PLACEHOLDERS:
        return True
    if any(p in clean for p in [
        "dummy", "fake", "placeholder", "your_key", "your_secret", "sample",
        "insert_", "replace_", "example_", "<your", "todo", "changeme", "***"
    ]):
        return True
    if clean.startswith("$") or clean.startswith("${") or "os.environ" in clean or "process.env" in clean:
        return True
    if len(set(clean)) <= 2:
        return True
    return False
