# ===================================================
# PowerShell Webhook Service Runner (with .env support)
# run command: ( powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1 )
# ===================================================

param([int]$Port = 8090)

# --- Load environment variables from .env ---
$envFile = ".\.env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.+)$') {
            Set-Item -Path Env:$($matches[1].Trim()) -Value $matches[2].Trim()
        }
    }
    Write-Host "Environment variables loaded from .env"
} else {
    Write-Warning ".env file not found, using already set environment variables."
}

# --- Script variables from environment ---
$DELINEA_BASE        = if ($env:DELINEA_BASE) { $env:DELINEA_BASE.TrimEnd('/') } else { '' }
$DELINEA_CLIENT_ID   = $env:DELINEA_CLIENT_ID
$DELINEA_CLIENT_SECRET = $env:DELINEA_CLIENT_SECRET
$ZOHO_CLIENT_ID      = $env:ZOHO_CLIENT_ID
$ZOHO_CLIENT_SECRET  = $env:ZOHO_CLIENT_SECRET
$ZOHO_REFRESH_TOKEN  = $env:ZOHO_REFRESH_TOKEN
$global:ZOHO_TOKEN   = $null
$global:ZOHO_TOKEN_LAST_REFRESH = $null
$ZOHO_REGION         = if ($env:ZOHO_REGION) { $env:ZOHO_REGION } else { 'in' }
$HMAC_SECRET         = $env:HMAC_SECRET
$MAX_RETRY           = if ($env:MAX_RETRY) { [int]$env:MAX_RETRY } else { 5 }
$DEFAULT_TTL_HOURS   = if ($env:ESCALATION_TTL_HOURS_DEFAULT) { [int]$env:ESCALATION_TTL_HOURS_DEFAULT } else { 8 }

# --- Check required environment variables ---
if (-not $DELINEA_BASE -or -not $DELINEA_CLIENT_ID -or -not $DELINEA_CLIENT_SECRET) {
    Write-Error "Missing required Delinea environment variables."
    exit 1
}
if (-not $ZOHO_CLIENT_ID -or -not $ZOHO_CLIENT_SECRET -or -not $ZOHO_REFRESH_TOKEN) {
    Write-Error "Missing required Zoho environment variables."
    exit 1
}

# --- Import the main webhook script ---
. .\webhook.ps1   # <-- This should be your main webhook script with all functions

# --- Start the listener ---
Start-Listener -port $Port
