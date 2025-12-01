# start-webhook.ps1
$envFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) '.env'

if (Test-Path $envFile) {
    Write-Host "Loading environment variables from $envFile"
    $envCount = 0
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { return }
        $parts = $line -split '=', 2
        if ($parts.Length -eq 2) {
            $name = $parts[0].Trim()
            $rawValue = $parts[1].Trim()
            $value = $rawValue
            if ($rawValue.StartsWith("'") -and $rawValue.EndsWith("'")) {
                $value = $rawValue.Substring(1, $rawValue.Length - 2)
            }
            elseif ($rawValue.StartsWith('"') -and $rawValue.EndsWith('"')) {
                $value = $rawValue.Substring(1, $rawValue.Length - 2)
            }
            [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
            $envCount++
        }
    }
    Write-Host "Loaded $envCount environment variables" -ForegroundColor Green
} else {
    Write-Host "No .env file found, using system environment variables" -ForegroundColor Yellow
}

$scriptPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) 'webhook.ps1'
if (-not (Test-Path $scriptPath)) {
    Write-Error "webhook.ps1 not found at $scriptPath"
    exit 1
}
Write-Host "Sourcing webhook.ps1..." -ForegroundColor Cyan
. $scriptPath

try { Start-RevokeWorker } catch { Write-Warning "RevokeWorker failed: $($_.Exception.Message)" }
try { Start-Listener } catch { Write-Error "Listener failed"; exit 1 }

while ($true) { Start-Sleep -Seconds 300 }
