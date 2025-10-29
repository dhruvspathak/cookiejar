# PowerShell Webhook Service for Automated Access Management via Delinea Secret Server
# Listens for approval comments or workitem state changes from Zoho Sprints and grants/revokes access

# TODO:
# Check with Nikhil for the Delinea permissions and credentials part
# Check with Fiona for Zoho fileds and approvers part
# Host on ngrok, create webhook with Fiona in Zoho
# Finally, a dry run :)

param([int]$Port = 8090)

# === ENVIRONMENT VARIABLES ===
$DELINEA_BASE       = if ($env:DELINEA_BASE) { $env:DELINEA_BASE.TrimEnd('/') } else { '' }
$DELINEA_CLIENT_ID  = $env:DELINEA_CLIENT_ID
$DELINEA_CLIENT_SECRET = $env:DELINEA_CLIENT_SECRET

$ZOHO_CLIENT_ID     = $env:ZOHO_CLIENT_ID
$ZOHO_CLIENT_SECRET = $env:ZOHO_CLIENT_SECRET
$ZOHO_REFRESH_TOKEN = $env:ZOHO_REFRESH_TOKEN
$global:ZOHO_TOKEN  = $null
$global:ZOHO_TOKEN_LAST_REFRESH = $null

$ZOHO_REGION        = if ($env:ZOHO_REGION) { $env:ZOHO_REGION } else { 'com' }
$HMAC_SECRET        = $env:HMAC_SECRET
$MAX_RETRY          = if ($env:MAX_RETRY) { [int]$env:MAX_RETRY } else { 5 }
$DEFAULT_TTL_HOURS  = if ($env:ESCALATION_TTL_HOURS_DEFAULT) { [int]$env:ESCALATION_TTL_HOURS_DEFAULT } else { 8 }

# === SENIOR APPROVERS FROM ENV ===
$senior = if ($env:SENIOR_APPROVERS) {
    $env:SENIOR_APPROVERS -split ','
} else {
    @()  # empty array if not set
}

if (-not $DELINEA_BASE -or -not $DELINEA_CLIENT_ID -or -not $DELINEA_CLIENT_SECRET) {
    Write-Error "Missing required Delinea environment variables (DELINEA_BASE, DELINEA_CLIENT_ID, DELINEA_CLIENT_SECRET)."
    exit 1
}

# === LOGGING ===
function Log($level, $message, $props = $null) {
    $ts = (Get-Date).ToString("o")
    $payload = @{ ts = $ts; level = $level; msg = $message }
    if ($props) { $payload.props = $props }
    $payload | ConvertTo-Json -Compress | Write-Output
}

# === DELINEA TOKEN ===
function Get-DelineaToken {
    $uri = "$DELINEA_BASE/oauth2/token"
    $body = @{ grant_type='client_credentials'; client_id=$DELINEA_CLIENT_ID; client_secret=$DELINEA_CLIENT_SECRET }
    $attempt = 0
    while ($true) {
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -TimeoutSec 30
            return $resp.access_token
        } catch {
            $attempt++; if ($attempt -ge $MAX_RETRY) { throw $_ } ; Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

function Invoke-DelineaGrant {
    param($bearer, $delineaUser, $roleName)
    $uri = "$DELINEA_BASE/api/roles/assign"
    $headers = @{ Authorization = "Bearer $bearer"; "Content-Type" = "application/json" }
    $payload = @{ userName = $delineaUser; roleName = $roleName } | ConvertTo-Json
    $attempt = 0
    while ($true) {
        try { return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payload -TimeoutSec 30 } catch {
            $attempt++; if ($attempt -ge $MAX_RETRY) { throw $_ } ; Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

function Invoke-DelineaRevoke {
    param($bearer, $delineaUser, $roleName)
    $uri = "$DELINEA_BASE/api/roles/unassign"
    $headers = @{ Authorization = "Bearer $bearer"; "Content-Type" = "application/json" }
    $payload = @{ userName = $delineaUser; roleName = $roleName } | ConvertTo-Json
    $attempt = 0
    while ($true) {
        try { return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payload -TimeoutSec 30 } catch {
            $attempt++; if ($attempt -ge $MAX_RETRY) { throw $_ } ; Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

# === ZOHO TOKEN MANAGEMENT ===
function Get-ZohoToken {
    if (-not $ZOHO_CLIENT_ID -or -not $ZOHO_CLIENT_SECRET -or -not $ZOHO_REFRESH_TOKEN) {
        throw "Missing ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET or ZOHO_REFRESH_TOKEN"
    }

    $now = Get-Date
    if ($global:ZOHO_TOKEN -and $global:ZOHO_TOKEN_LAST_REFRESH -and ($now - $global:ZOHO_TOKEN_LAST_REFRESH).TotalMinutes -lt 50) {
        return $global:ZOHO_TOKEN
    }

    $tokenUrl = "https://accounts.zoho.$ZOHO_REGION/oauth/v2/token"
    $body = @{
        refresh_token = $ZOHO_REFRESH_TOKEN
        client_id     = $ZOHO_CLIENT_ID
        client_secret = $ZOHO_CLIENT_SECRET
        grant_type    = 'refresh_token'
    }

    try {
        $resp = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -TimeoutSec 30
        if ($resp.access_token) {
            $global:ZOHO_TOKEN = $resp.access_token
            $global:ZOHO_TOKEN_LAST_REFRESH = Get-Date
            return $resp.access_token
        } else {
            throw "No access_token in response: $($resp | ConvertTo-Json -Compress)"
        }
    } catch {
        throw "Failed to refresh Zoho token: $($_.Exception.Message)"
    }
}

function Post-ZohoComment {
    param($workitemId, $message)
    try {
        $token = Get-ZohoToken
        $headers = @{ Authorization = "Zoho-oauthtoken $token"; "Content-Type" = "application/json" }
        $body = @{ comment = $message } | ConvertTo-Json
        $url = "https://sprintsapi.zoho.$ZOHO_REGION/api/v3/workitems/$workitemId/comments"
        Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -TimeoutSec 30
    } catch {
        Log 'WARN' "Failed to post comment to Zoho" @{ workitem = $workitemId; err = $_.Exception.Message }
    }
}

# === FIELD PARSING ===
function ParseDurationToHours {
    param([string]$raw)
    if (-not $raw) { return $DEFAULT_TTL_HOURS }
    $r = $raw.Trim().ToLower()
    if ($r -match '^\d+$') { return [int]$r }
    if ($r -match '^(\d+)\s*h(?:ours?)?$') { return [int]$matches[1] }
    if ($r -match '^(\d+)\s*d(?:ays?)?$') { return [int]$matches[1] * 24 }
    if ($r -match '^(\d+)\s*m(?:in(?:utes?)?)?$') { return [int]([math]::Ceiling([int]$matches[1] / 60)) }
    if ($r -match '^(\d+)\s*hr?s?$') { return [int]$matches[1] }
    return $DEFAULT_TTL_HOURS
}

function Extract-ChangeReleaseFields {
    param([hashtable]$workitem)
    $fields = @{}
    foreach ($cf in $workitem.customFields) {
        switch -regex ($cf.name.ToLower()) {
            "server"   { $fields.server = $cf.value; continue }
            "assignee" { $fields.assignee = $cf.value; continue }
            "duration" { $fields.duration = $cf.value; continue }
        }
    }
    if (-not $fields.server)   { throw "Missing 'Server Name' in workitem" }
    if (-not $fields.assignee) { throw "Missing 'Assignee' in workitem" }
    if (-not $fields.duration) { $fields.duration = $DEFAULT_TTL_HOURS }
    return $fields
}

function Get-RoleForServer {
    param($server)
    if (-not $server) { return 'Default_Deploy_Role' }
    switch -wildcard ($server.ToLower()) {
        '*webapp*' { return 'WebApp_Deploy_Role' }
        '*db*'     { return 'DB_Readonly_Role' }
        '*prod*'   { return 'Prod_Deploy_Role' }
        default     { return 'Default_Deploy_Role' }
    }
}

# === ACCESS HANDLERS ===
function Handle-GrantAccess {
    param($workitemId, $projectName, $assigneeEmail, $ticketUrl, $server, $durationRaw, $targetUser)
    $durationHours = ParseDurationToHours -raw $durationRaw
    $role = Get-RoleForServer -server $server
    $dUser = if ($targetUser) { $targetUser } else { $assigneeEmail }
    if (-not $dUser) {
        Log 'ERROR' 'No target user resolved; aborting' @{ workitem = $workitemId }
        Post-ZohoComment -workitemId $workitemId -message "Failed to grant access: cannot resolve target user."
        return
    }
    $token = Get-DelineaToken
    try {
        Invoke-DelineaGrant -bearer $token -delineaUser $dUser -roleName $role
        $expiresAt = (Get-Date).AddHours($durationHours).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $message = "Access GRANTED to $dUser on server [$server] (role: $role) until $expiresAt. Duration: $durationHours hours."
        Post-ZohoComment -workitemId $workitemId -message $message
        Log 'INFO' 'Access granted' @{ workitem = $workitemId; user = $dUser; role = $role; server = $server; durationH = $durationHours }
    } catch {
        Log 'ERROR' 'Grant failed' @{ workitem = $workitemId; err = $_.Exception.Message }
        Post-ZohoComment -workitemId $workitemId -message "Error granting access: $($_.Exception.Message)"
    }
}

function Handle-Revoke {
    param($workitemId, $workitem)
    try {
        $fields = Extract-ChangeReleaseFields -workitem $workitem
        $server = $fields.server
        $target = $fields.assignee
        $role = Get-RoleForServer -server $server
        if (-not $target) {
            Log 'WARN' 'No target found for revoke' @{ workitem = $workitemId }
            Post-ZohoComment -workitemId $workitemId -message "Revoke: no target user found."
            return
        }
        $token = Get-DelineaToken
        Invoke-DelineaRevoke -bearer $token -delineaUser $target -roleName $role
        Post-ZohoComment -workitemId $workitemId -message "Temporary access revoked for $target (role: $role)."
        Log 'INFO' 'Revoked' @{ workitem = $workitemId; user = $target; role = $role }
    } catch {
        Log 'ERROR' 'Revoke failed' @{ workitem = $workitemId; err = $_.Exception.Message }
        Post-ZohoComment -workitemId $workitemId -message "Error revoking access: $($_.Exception.Message)"
    }
}

# === MAIN WEBHOOK LISTENER ===
function Start-Listener {
    param([int]$port = 8090)
    $prefix = "http://*:$port/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix)
    $listener.Start()
    Log 'INFO' 'Listener started' @{ prefix = $prefix }

    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        Start-Job -ArgumentList $ctx -ScriptBlock {
            param($ctx)
            try {
                $req = $ctx.Request
                $body = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
                $receivedHmac = $req.Headers['X-Zoho-Signature']
                if ($receivedHmac) {
                    $hmacKey = [System.Text.Encoding]::UTF8.GetBytes($env:HMAC_SECRET)
                    $hashAlg = New-Object System.Security.Cryptography.HMACSHA256($hmacKey)
                    $calc = $hashAlg.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
                    $calcB64 = [System.Convert]::ToBase64String($calc)
                    if ($calcB64 -ne $receivedHmac) { $ctx.Response.StatusCode = 401; $ctx.Response.Close(); return }
                }

                $payloadRaw = $body | ConvertFrom-Json
                $eventType = $payloadRaw.event
                $workitem = $payloadRaw.data.workitem

                if ($eventType -eq 'comment.added') {
                    $workitemId = $workitem.id
                    $projectName = $workitem.project.name
                    $assigneeEmail = $workitem.assignee.email
                    $fields = Extract-ChangeReleaseFields -workitem $workitem
                    $server   = $fields.server
                    $duration = $fields.duration
                    $target   = $fields.assignee
                    $lastComment = if ($workitem.comments -and $workitem.comments.Count -gt 0) { $workitem.comments[-1] } else { $null }
                    if ($lastComment -and $lastComment.comment_text.Trim().ToLower() -eq 'approved') {
                        $author = $lastComment.author.email
                        if ($senior -contains $author) {
                            Handle-GrantAccess -workitemId $workitemId -projectName $projectName -assigneeEmail $assigneeEmail -ticketUrl $workitem.url -server $server -durationRaw $duration -targetUser $target
                        }
                    }
                } elseif ($eventType -eq 'workitem.updated') {
                    $workitemId = $workitem.id
                    $status = $workitem.status
                    if ($status -in @('Closed','Completed','Done')) {
                        Handle-Revoke -workitemId $workitemId -workitem $workitem
                    }
                }

                $ctx.Response.StatusCode = 200
                $ctx.Response.Close()
            } catch {
                Log 'ERROR' "Listener job exception: $($_.Exception.Message)"
                try { $ctx.Response.StatusCode = 500; $ctx.Response.Close() } catch {}
            }
        } | Out-Null
    }
}

Start-Listener -port $Port
