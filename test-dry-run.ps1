# Test helper script - sends test payload with HMAC signature
# Run this AFTER webhook, mock-zoho, and mock-delinea are running

# HMAC signature function (same as in webhook.ps1)
function New-ZohoSignature {
    param($body, $secret)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
    return [Convert]::ToBase64String($hash)
}

Write-Host "Loading test payload..." -ForegroundColor Cyan
$body = Get-Content approve.json -Raw

$secret = 'local_test_secret'
$sig = New-ZohoSignature -body $body -secret $secret

Write-Host "Computed Signature: $sig" -ForegroundColor Yellow

Write-Host "`nSending test approval to webhook..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8090/" `
        -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "X-Zoho-Signature" = $sig
        } `
        -Body $body `
        -ErrorAction Stop
    
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "Response: $($response.Content)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to send request: $_"
    Write-Error "Response: $($_.Exception.Response)"
}

Write-Host "`nTest complete. Check webhook, mock-zoho, and mock-delinea console outputs for activity." -ForegroundColor Cyan
