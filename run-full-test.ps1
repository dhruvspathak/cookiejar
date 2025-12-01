# Full dry run test with validation

Write-Host "====== WEBHOOK SERVICE DRY RUN TEST ======" -ForegroundColor Cyan

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
Write-Host "1. Services Status:" -ForegroundColor Yellow
$services = @(
    @{ Name = "Mock Delinea"; Port = 19002 },
    @{ Name = "Mock Zoho"; Port = 19001 },
    @{ Name = "Webhook"; Port = 9090 }
)

foreach ($svc in $services) {
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
Write-Host "2. Sending Test Request:" -ForegroundColor Yellow
$secret = 'local_test_secret'
$sig = New-ZohoSignature -body $testPayload -secret $secret
Write-Host "   Signature: $($sig.Substring(0,20))..." -ForegroundColor Gray

try {
    $uri = "http://127.0.0.1:9090/"
    Write-Host "   POST to $uri" -ForegroundColor Gray
    
    $response = Invoke-WebRequest -Uri $uri `
        -Method POST `
        -Headers @{
        "Content-Type" = "application/json"
        "X-Zoho-Signature" = $sig
    } `
        -Body $testPayload `
        -ErrorAction Stop `
        -TimeoutSec 5
    
    Write-Host "    HTTP Status: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "    Response: $($response.Content)" -ForegroundColor Green
}
catch [System.Net.WebException] {
    Write-Host "    Connection Error: $($_.Exception.Message)" -ForegroundColor Red
}
catch [System.TimeoutException] {
    Write-Host "    Timeout connecting to webhook" -ForegroundColor Red
}
catch {
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "3. Checking Grants File:" -ForegroundColor Yellow
$grantsFile = "grants.jsonl"
if (Test-Path $grantsFile) {
    $content = Get-Content $grantsFile -Raw
    Write-Host "    $grantsFile exists" -ForegroundColor Green
    Write-Host "   Content (first 200 chars):" -ForegroundColor Gray
    Write-Host "   $($content.Substring(0, [math]::Min(200, $content.Length)))" -ForegroundColor Gray
}
else {
    Write-Host "   ℹ $grantsFile not yet created (normal for test)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "====== TEST COMPLETE ======" -ForegroundColor Cyan
