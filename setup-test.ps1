# Quick setup script - Creates .env file for local testing with mock APIs

Write-Host "Creating .env file for local testing..." -ForegroundColor Green

$envContent = @"
# Local test configuration
PORT=8090
HMAC_SECRET=local_test_secret
HMAC_REQUIRED=true

# Mock APIs (local)
ZOHO_API_BASE=http://localhost:19001
ZOHO_CLIENT_ID=mock
ZOHO_CLIENT_SECRET=mock

DELINEA_API_BASE=http://localhost:19002
DELINEA_CLIENT_ID=mock
DELINEA_CLIENT_SECRET=mock

# Test approver
SENIOR_APPROVERS=alice@example.com
"@

$envContent | Set-Content -Path ".env" -Encoding UTF8
Write-Host ".env file created successfully" -ForegroundColor Green
Write-Host "Contents:" -ForegroundColor Yellow
Write-Host $envContent
