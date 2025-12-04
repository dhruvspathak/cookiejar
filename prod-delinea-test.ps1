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
Write-Host "2. Testing Delinea Connectivity:" -ForegroundColor Yellow

$delineaBase = $env_vars['DELINEA_API_BASE']
$clientId = $env_vars['DELINEA_CLIENT_ID']
$clientSecret = $env_vars['DELINEA_CLIENT_SECRET']

# Test if Delinea API is reachable
try {
    Write-Host "   Testing connection to: $delineaBase" -ForegroundColor Gray
    
    # Try to reach the Delinea API
    $testUri = "$delineaBase/Security/StartChallenge"
    Write-Host "   POST $testUri" -ForegroundColor Gray
    
    $challengeBody = @{
        TenantId = ""
        User = $clientId
        Version = "1.0"
        AssociatedEntityType = "API"
        AssociatedEntityName = "CookieJar-Test"
    } | ConvertTo-Json -Compress
    
    Write-Host ""
    Write-Host "3. Attempting OAuth2 Authentication with Production Delinea:" -ForegroundColor Yellow
    Write-Host "   Sending /Security/StartChallenge..." -ForegroundColor Gray
    
    $challengeResp = Invoke-RestMethod -Uri $testUri -Method Post -Body $challengeBody `
        -Headers @{ 'Content-Type' = 'application/json' } `
        -ErrorAction Stop -TimeoutSec 15
    
    if ($challengeResp.success) {
        Write-Host "   OK Challenge received from Delinea" -ForegroundColor Green
        Write-Host "   OK SessionId: $($challengeResp.Result.SessionId.Substring(0, 20))..." -ForegroundColor Green
        Write-Host "   OK TenantId: $($challengeResp.Result.TenantId)" -ForegroundColor Green
        
        # Now advance authentication
        Write-Host ""
        Write-Host "   Sending /Security/AdvanceAuthentication..." -ForegroundColor Gray
        
        $sessionId = $challengeResp.Result.SessionId
        $tenantId = $challengeResp.Result.TenantId
        $mechanismId = $challengeResp.Result.Challenges[0].Mechanisms[0].MechanismId
        
        $advanceUri = "$delineaBase/Security/AdvanceAuthentication"
        $advanceBody = @{
            TenantId = $tenantId
            SessionId = $sessionId
            MechanismId = $mechanismId
            Answer = $clientSecret
            Action = "Answer"
        } | ConvertTo-Json -Compress
        
        $advanceResp = Invoke-RestMethod -Uri $advanceUri -Method Post -Body $advanceBody `
            -Headers @{ 'Content-Type' = 'application/json' } `
            -ErrorAction Stop -TimeoutSec 15
        
        if (($advanceResp.success) -and ($advanceResp.Result.Auth)) {
            $token = $advanceResp.Result.Auth
            Write-Host "   OK Authentication SUCCESSFUL" -ForegroundColor Green
            Write-Host "   OK Bearer Token: $($token.Substring(0, 30))..." -ForegroundColor Green
            Write-Host "   OK User: $($advanceResp.Result.User)" -ForegroundColor Green
            Write-Host "   OK AuthLevel: $($advanceResp.Result.AuthLevel)" -ForegroundColor Green
            
            Write-Host ""
            Write-Host "4. Configuration Summary:" -ForegroundColor Yellow
            Write-Host "   OK Production Delinea is reachable" -ForegroundColor Green
            Write-Host "   OK Credentials are valid" -ForegroundColor Green
            Write-Host "   OK OAuth2 authentication working" -ForegroundColor Green
            Write-Host ""
            Write-Host "   Ready to run: powershell -File .\run-full-test.ps1" -ForegroundColor Green
        }
        else {
            Write-Host "   FAILED Authentication failed" -ForegroundColor Red
            Write-Host "   Response: $($advanceResp | ConvertTo-Json)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "   FAILED Challenge failed" -ForegroundColor Red
        Write-Host "   Response: $($challengeResp | ConvertTo-Json)" -ForegroundColor Red
    }
}
catch {
    Write-Host "   FAILED Error during authentication test" -ForegroundColor Red
    $errorMsg = $_.Exception.Message
    Write-Host "   Error: $errorMsg" -ForegroundColor Red
    
    # Provide more specific troubleshooting info
    if ($errorMsg -like "*404*") {
        Write-Host ""
        Write-Host "   NOTE: 404 Not Found suggests incorrect API endpoint path" -ForegroundColor Yellow
        Write-Host "   Possible issues:" -ForegroundColor Yellow
        Write-Host "   - The endpoint path might have changed in your Delinea version" -ForegroundColor Yellow
        Write-Host "   - Check your Delinea API documentation for correct authentication endpoints" -ForegroundColor Yellow
        Write-Host "   - Try using: /uprest/Security/StartChallenge instead" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "   Troubleshooting:" -ForegroundColor Yellow
    Write-Host "   1. Verify DELINEA_API_BASE is correct: $delineaBase" -ForegroundColor Yellow
    Write-Host "   2. Check network connectivity (firewall/proxy)" -ForegroundColor Yellow
    Write-Host "   3. Verify credentials: $clientId" -ForegroundColor Yellow
    Write-Host "   4. Check Delinea API documentation for correct endpoint paths" -ForegroundColor Yellow
    if ($_.Exception.Response) {
        Write-Host "   5. HTTP Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "====== TEST COMPLETE ======" -ForegroundColor Cyan
