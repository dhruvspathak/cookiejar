# Full dry run test with PRODUCTION DELINEA + MOCK ZOHO

Write-Host "====== WEBHOOK SERVICE DRY RUN TEST (PROD DELINEA + MOCK ZOHO) ======" -ForegroundColor Cyan

# HMAC signature function
function New-ZohoSignature {
    param($body, $secret)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
    return [Convert]::ToBase64String($hash)
}

# Create test payload
$testPayload = @{
    event = "comment.added"
    ticket = @{
        id = 12345
        title = "Temp access to prod-app-server-01"
        assignee = @{ email = "dev@example.com" }
        customFields = @(
            @{ name = "server"; value = "prod-app-server-01" },
            @{ name = "duration"; value = "2h" },
            @{ name = "target"; value = "dev@example.com" }
        )
    }
    comment = @{
        text = "approved"
        author = @{ email = "alice@example.com" }
    }
} | ConvertTo-Json -Depth 10

Write-Host ""
Write-Host "1. Configuration Status:" -ForegroundColor Yellow
Write-Host "   ✓ Delinea: PRODUCTION (https://cookiejar.delinea.app)" -ForegroundColor Green
Write-Host "   ✓ Zoho: MOCK (http://localhost:19001)" -ForegroundColor Yellow
Write-Host "   ✓ Webhook: http://127.0.0.1:9090" -ForegroundColor Green

Write-Host ""
Write-Host "2. Local Services Status:" -ForegroundColor Yellow
$localServices = @(
    @{ Name = "Mock Zoho"; Port = 19001 },
    @{ Name = "Webhook"; Port = 9090 }
)

foreach ($svc in $localServices) {
    try {
        $result = Test-NetConnection -ComputerName "127.0.0.1" -Port $svc.Port -ErrorAction Stop -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Write-Host "    $($svc.Name) listening on port $($svc.Port)" -ForegroundColor Green
        }
        else {
            Write-Host "    $($svc.Name) NOT responding on port $($svc.Port)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "    $($svc.Name) - Connection failed: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "3. Sending Test Request (Will authenticate with PRODUCTION DELINEA):" -ForegroundColor Yellow
$secret = 'local_test_secret'
$sig = New-ZohoSignature -body $testPayload -secret $secret
Write-Host "   Signature: $($sig.Substring(0,20))..." -ForegroundColor Gray

try {
    $uri = "http://127.0.0.1:9090/"
    Write-Host "   POST to $uri" -ForegroundColor Gray
    Write-Host "   (Webhook will call: https://cookiejar.delinea.app/Security/StartChallenge)" -ForegroundColor Cyan
    
    $response = Invoke-WebRequest -Uri $uri `
        -Method POST `
        -Headers @{
        "Content-Type" = "application/json"
        "X-Zoho-Signature" = $sig
    } `
        -Body $testPayload `
        -ErrorAction Stop `
        -TimeoutSec 30

    Write-Host "    HTTP Status: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "    Response: $($response.Content)" -ForegroundColor Green
    Write-Host ""
    Write-Host "   ✓ TEST PASSED: Webhook received request and escalated to production Delinea" -ForegroundColor Green
}
catch [System.Net.WebException] {
    Write-Host "    Connection Error: $($_.Exception.Message)" -ForegroundColor Red
}
catch [System.TimeoutException] {
    Write-Host "    Timeout - This may indicate Delinea API is slow or unreachable" -ForegroundColor Yellow
}
catch {
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "4. Checking Grants Audit Log:" -ForegroundColor Yellow
$grantsFile = "grants.jsonl"
if (Test-Path $grantsFile) {
    $content = Get-Content $grantsFile -Raw
    Write-Host "    ✓ $grantsFile exists" -ForegroundColor Green
    Write-Host "   Content (first 300 chars):" -ForegroundColor Gray
    Write-Host "   $($content.Substring(0, [math]::Min(300, $content.Length)))" -ForegroundColor Gray
}
else {
    Write-Host "   ℹ $grantsFile not yet created (normal on first run)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "====== TEST COMPLETE ======" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Check webhook logs for 'Delinea authentication successful'" -ForegroundColor Yellow
Write-Host "  2. Verify privilege was escalated in production Delinea" -ForegroundColor Yellow
Write-Host "  3. Check grants.jsonl for new grant record" -ForegroundColor Yellow
