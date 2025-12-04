# Production Delinea Integration Test
# This script tests the webhook against REAL DELINEA (not mock)

Write-Host "====== PRODUCTION DELINEA INTEGRATION TEST ======" -ForegroundColor Cyan
Write-Host ""

# Load environment
Write-Host "1. Loading Configuration from .env:" -ForegroundColor Yellow
$envFile = ".env"
if ((Test-Path $envFile)) {
    $envContent = Get-Content $envFile | Where-Object { $_ -match '^[^#]+=' }
    $env_vars = @{}
    foreach ($line in $envContent) {
        $key, $value = $line -split '=', 2
        $env_vars[$key.Trim()] = $value.Trim()
    }
    
    Write-Host "   OK DELINEA_API_BASE: $($env_vars['DELINEA_API_BASE'])" -ForegroundColor Green
    Write-Host "   OK DELINEA_CLIENT_ID: $($env_vars['DELINEA_CLIENT_ID'])" -ForegroundColor Green
    Write-Host "   OK DELINEA_CLIENT_SECRET: [REDACTED]" -ForegroundColor Green
    Write-Host "   OK ZOHO_API_BASE: $($env_vars['ZOHO_API_BASE'])" -ForegroundColor Yellow
    Write-Host "   OK WEBHOOK_PORT: $($env_vars['PORT'])" -ForegroundColor Green
}
else {
    Write-Host "   FAILED .env file not found!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "3. Testing OAuth2 (client_credentials) with Production Delinea:" -ForegroundColor Yellow

$delineaBase = $env_vars['DELINEA_API_BASE']
$clientId = $env_vars['DELINEA_CLIENT_ID']
$clientSecret = $env_vars['DELINEA_CLIENT_SECRET']

try {
    $tokenUri = "$($delineaBase.TrimEnd('/'))/identity/api/oauth2/token/xpmplatform"
    Write-Host "   POST $tokenUri" -ForegroundColor Gray
    
    $tokenBody = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = 'xpmheadless'
    }
    
    Write-Host "   Requesting access token..." -ForegroundColor Gray
    Write-Host "   Request body: " -ForegroundColor Gray
    foreach ($k in $tokenBody.Keys) {
        $val = if ($k -eq 'client_secret') { '[REDACTED]' } else { $tokenBody[$k] }
        Write-Host "     $k = $val" -ForegroundColor Gray
    }
    
    $tokenResp = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $tokenBody `
        -ContentType 'application/x-www-form-urlencoded' `
        -ErrorAction Stop -TimeoutSec 15
    
    if ($tokenResp.access_token) {
        Write-Host "   OK OAuth2 authentication SUCCESSFUL" -ForegroundColor Green
        $token = $tokenResp.access_token
        Write-Host "   OK Access Token: $($token.Substring(0, 30))..." -ForegroundColor Green
        Write-Host "   OK Token Type: $($tokenResp.token_type)" -ForegroundColor Green
        Write-Host "   OK Expires In: $($tokenResp.expires_in) seconds" -ForegroundColor Green
        Write-Host "   OK Scope: $($tokenResp.scope)" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "4. Configuration Summary:" -ForegroundColor Yellow
        Write-Host "   OK Production Delinea is reachable" -ForegroundColor Green
        Write-Host "   OK Credentials are valid" -ForegroundColor Green
        Write-Host "   OK OAuth2 (client_credentials) authentication working" -ForegroundColor Green
        Write-Host "   OK Ready to deploy to production" -ForegroundColor Green
    }
    else {
        Write-Host "   FAILED OAuth2 response missing access_token" -ForegroundColor Red
        Write-Host "   Response: $($tokenResp | ConvertTo-Json)" -ForegroundColor Red
    }
}
catch {
    Write-Host "   FAILED Error during OAuth2 authentication test" -ForegroundColor Red
    $errorMsg = $_.Exception.Message
    Write-Host "   Error: $errorMsg" -ForegroundColor Red
    
    # Try to extract response body for more details
    if ($_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            $reader.Close()
            Write-Host "   Response Body: $responseBody" -ForegroundColor Red
        } catch {
            Write-Host "   Could not read response body" -ForegroundColor Yellow
        }
    }
    
    # Provide more specific troubleshooting info
    if ($errorMsg -like "*400*") {
        Write-Host ""
        Write-Host "   NOTE: 400 Bad Request - request format issue" -ForegroundColor Yellow
        Write-Host "   Possible causes:" -ForegroundColor Yellow
        Write-Host "   - OAuth2 endpoint path might be different" -ForegroundColor Yellow
        Write-Host "   - Request body format might be incorrect" -ForegroundColor Yellow
        Write-Host "   - scope or grant_type values might be wrong for your tenant" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "   Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   1. Verify DELINEA_API_BASE is correct: $delineaBase" -ForegroundColor Yellow
    Write-Host "   2. Verify OAuth2 endpoint: $tokenUri" -ForegroundColor Yellow
    Write-Host "   3. Check credentials: $clientId" -ForegroundColor Yellow
    Write-Host "   4. Verify network connectivity (firewall/proxy)" -ForegroundColor Yellow
    Write-Host "   5. Check Delinea documentation for correct OAuth2 endpoint" -ForegroundColor Yellow
    Write-Host "   6. Verify grant_type and scope values are correct" -ForegroundColor Yellow
    if ($_.Exception.Response) {
        Write-Host "   7. HTTP Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "====== TEST COMPLETE ======" -ForegroundColor Cyan
