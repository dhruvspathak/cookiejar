# PowerShell Webhook Service for Automated Access Management via Delinea Secret Server
# Listens for approval comments or workitem state changes from Zoho Sprints and grants/revokes access

# TODO:
# Check with Nikhil for the Delinea permissions and credentials part
# Check with Fiona for Zoho fileds and approvers part
# Host on ngrok, create webhook with Fiona in Zoho
# Finally, a dry run :)

# ...existing code...
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
function Redact-ForLog {
    param($obj)
    # Shallow redact common secret keys to avoid leaking tokens/secrets in logs.
    try {
        if ($null -eq $obj) { return $null }
        if ($obj -is [string]) {
            return $obj
        }
        if ($obj -is [System.Collections.IDictionary]) {
            $copy = @{}
            foreach ($k in $obj.Keys) {
                $lk = $k.ToString().ToLower()
                if ($lk -match 'secret|token|password|authorization|client_secret|refresh_token') {
                    $copy[$k] = 'REDACTED'
                } else {
                    $copy[$k] = $obj[$k]
                }
            }
            return $copy
        }
        return $obj
    } catch {
        return 'REDACTED'
    }
}

function Log($level, $message, $props = $null) {
    $ts = (Get-Date).ToString("o")
    $payload = @{ ts = $ts; level = $level; msg = $message }
    if ($props) {
        $payload.props = Redact-ForLog($props)
    }
    # Ensure we always emit JSON; if serialization fails, fall back to plain message.
    try {
        $payload | ConvertTo-Json -Compress | Write-Output
    } catch {
        @{ ts = $ts; level = $level; msg = $message; props = 'UNSERIALIZABLE' } | ConvertTo-Json -Compress | Write-Output
    }
}

# ...existing code...
# === DELINEA TOKEN ===
function Get-DelineaToken {
    $uri = "$DELINEA_BASE/oauth2/token"
    $body = @{ grant_type='client_credentials'; client_id=$DELINEA_CLIENT_ID; client_secret='REDACTED' }
    $attempt = 0
    Log 'DEBUG' "Requesting Delinea token" @{ uri = $uri; attempt = $attempt }
    while ($true) {
        try {
            # For HTTP body we must avoid logging client_secret; send actual secret to the request separately.
            $realBody = @{ grant_type='client_credentials'; client_id=$DELINEA_CLIENT_ID; client_secret=$DELINEA_CLIENT_SECRET }
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $realBody -TimeoutSec 30
            Log 'INFO' "Delinea token retrieved" @{ length = ($resp.access_token.Length); at = (Get-Date).ToString("o") }
            return $resp.access_token
        } catch {
            $attempt++
            Log 'WARN' "Get-DelineaToken attempt failed" @{ uri = $uri; attempt = $attempt; err = $_.Exception.Message }
            if ($attempt -ge $MAX_RETRY) { 
                Log 'ERROR' "Exceeded Delinea token retries" @{ uri = $uri; attempts = $attempt }
                throw $_ 
            }
            Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

function Invoke-DelineaGrant {
    param($bearer, $delineaUser, $roleName)
    $uri = "$DELINEA_BASE/api/roles/assign"
    $headers = @{ Authorization = "Bearer REDACTED"; "Content-Type" = "application/json" }
    $payload = @{ userName = $delineaUser; roleName = $roleName } | ConvertTo-Json
    $attempt = 0
    Log 'DEBUG' "Invoke-DelineaGrant starting" @{ uri = $uri; user = $delineaUser; role = $roleName }
    while ($true) {
        try { 
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $bearer"; "Content-Type" = "application/json" } -Body $payload -TimeoutSec 30
            Log 'INFO' "Delinea grant succeeded" @{ user = $delineaUser; role = $roleName; uri = $uri }
            return $resp
        } catch {
            $attempt++
            Log 'WARN' "Delinea grant failed (will retry if attempts remain)" @{ user = $delineaUser; role = $roleName; attempt = $attempt; err = $_.Exception.Message }
            if ($attempt -ge $MAX_RETRY) { 
                Log 'ERROR' "Delinea grant exceeded retries" @{ user = $delineaUser; role = $roleName; attempts = $attempt }
                throw $_ 
            }
            Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

function Invoke-DelineaRevoke {
    param($bearer, $delineaUser, $roleName)
    $uri = "$DELINEA_BASE/api/roles/unassign"
    $headers = @{ Authorization = "Bearer REDACTED"; "Content-Type" = "application/json" }
    $payload = @{ userName = $delineaUser; roleName = $roleName } | ConvertTo-Json
    $attempt = 0
    Log 'DEBUG' "Invoke-DelineaRevoke starting" @{ uri = $uri; user = $delineaUser; role = $roleName }
    while ($true) {
        try { 
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $bearer"; "Content-Type" = "application/json" } -Body $payload -TimeoutSec 30
            Log 'INFO' "Delinea revoke succeeded" @{ user = $delineaUser; role = $roleName; uri = $uri }
            return $resp
        } catch {
            $attempt++
            Log 'WARN' "Delinea revoke failed (will retry if attempts remain)" @{ user = $delineaUser; role = $roleName; attempt = $attempt; err = $_.Exception.Message }
            if ($attempt -ge $MAX_RETRY) { 
                Log 'ERROR' "Delinea revoke exceeded retries" @{ user = $delineaUser; role = $roleName; attempts = $attempt }
                throw $_ 
            }
            Start-Sleep -Seconds ([math]::Pow(2,$attempt))
        }
    }
}

# ...existing code...
# === ZOHO TOKEN MANAGEMENT ===
function Get-ZohoToken {
    if (-not $ZOHO_CLIENT_ID -or -not $ZOHO_CLIENT_SECRET -or -not $ZOHO_REFRESH_TOKEN) {
        throw "Missing ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET or ZOHO_REFRESH_TOKEN"
    }

    $now = Get-Date
    if ($global:ZOHO_TOKEN -and $global:ZOHO_TOKEN_LAST_REFRESH -and ($now - $global:ZOHO_TOKEN_LAST_REFRESH).TotalMinutes -lt 50) {
        Log 'DEBUG' "Using cached Zoho token" @{ last_refresh = $global:ZOHO_TOKEN_LAST_REFRESH.ToString("o") }
        return $global:ZOHO_TOKEN
    }

    $tokenUrl = "https://accounts.zoho.$ZOHO_REGION/oauth/v2/token"
    $body = @{
        refresh_token = 'REDACTED'
        client_id     = $ZOHO_CLIENT_ID
        client_secret = 'REDACTED'
        grant_type    = 'refresh_token'
    }

    Log 'DEBUG' "Refreshing Zoho token" @{ url = $tokenUrl }
    try {
        $realBody = @{
            refresh_token = $ZOHO_REFRESH_TOKEN
            client_id     = $ZOHO_CLIENT_ID
            client_secret = $ZOHO_CLIENT_SECRET
            grant_type    = 'refresh_token'
        }
        $resp = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $realBody -TimeoutSec 30
        if ($resp.access_token) {
            $global:ZOHO_TOKEN = $resp.access_token
            $global:ZOHO_TOKEN_LAST_REFRESH = Get-Date
            Log 'INFO' "Zoho token refreshed" @{ at = $global:ZOHO_TOKEN_LAST_REFRESH.ToString("o") }
            return $resp.access_token
        } else {
            Log 'ERROR' "Zoho token refresh response missing access_token" @{ resp = Redact-ForLog($resp) }
            throw "No access_token in response: $($resp | ConvertTo-Json -Compress)"
        }
    } catch {
        Log 'ERROR' "Failed to refresh Zoho token" @{ err = $_.Exception.Message }
        throw "Failed to refresh Zoho token: $($_.Exception.Message)"
    }
}

function Post-ZohoComment {
    param($workitemId, $message)
    try {
        $token = Get-ZohoToken
        $headers = @{ Authorization = "Zoho-oauthtoken REDACTED"; "Content-Type" = "application/json" }
        $body = @{ comment = $message } | ConvertTo-Json
        $url = "https://sprintsapi.zoho.$ZOHO_REGION/api/v3/workitems/$workitemId/comments"
        Log 'DEBUG' "Posting Zoho comment" @{ workitem = $workitemId; url = $url; message = $message }
        Invoke-RestMethod -Uri $url -Method Post -Headers @{ Authorization = "Zoho-oauthtoken $token"; "Content-Type" = "application/json" } -Body $body -TimeoutSec 30
        Log 'INFO' "Posted comment to Zoho" @{ workitem = $workitemId }
    } catch {
        Log 'WARN' "Failed to post comment to Zoho" @{ workitem = $workitemId; err = $_.Exception.Message }
    }
}

# === FIELD PARSING ===
function ParseDurationToHours {
    param([string]$raw)
    if (-not $raw) { 
        Log 'DEBUG' "Duration not provided, using default" @{ default_hours = $DEFAULT_TTL_HOURS }
        return $DEFAULT_TTL_HOURS 
    }
    $r = $raw.Trim().ToLower()
    if ($r -match '^\d+$') { 
        Log 'DEBUG' "Parsed numeric duration" @{ raw = $raw; hours = [int]$r }
        return [int]$r 
    }
    if ($r -match '^(\d+)\s*h(?:ours?)?$') { 
        Log 'DEBUG' "Parsed hours duration" @{ raw = $raw; hours = [int]$matches[1] }
        return [int]$matches[1] 
    }
    if ($r -match '^(\d+)\s*d(?:ays?)?$') { 
        Log 'DEBUG' "Parsed days duration" @{ raw = $raw; hours = [int]$matches[1] * 24 }
        return [int]$matches[1] * 24 
    }
    if ($r -match '^(\d+)\s*m(?:in(?:utes?)?)?$') { 
        $val = [math]::Ceiling([int]$matches[1] / 60)
        Log 'DEBUG' "Parsed minutes duration to hours" @{ raw = $raw; hours = $val }
        return $val
    }
    if ($r -match '^(\d+)\s*hr?s?$') { 
        Log 'DEBUG' "Parsed hr/hrs duration" @{ raw = $raw; hours = [int]$matches[1] }
        return [int]$matches[1] 
    }
    Log 'DEBUG' "Could not parse duration, using default" @{ raw = $raw; default_hours = $DEFAULT_TTL_HOURS }
    return $DEFAULT_TTL_HOURS
}

function Extract-ChangeReleaseFields {
    param([hashtable]$workitem)
    $fields = @{ server = $null; assignee = $null; duration = $null }
    foreach ($cf in $workitem.customFields) {
        switch -regex ($cf.name.ToLower()) {
            "server"   { $fields.server = $cf.value; continue }
            "assignee" { $fields.assignee = $cf.value; continue }
            "duration" { $fields.duration = $cf.value; continue }
        }
    }
    if (-not $fields.server)   { 
        Log 'WARN' "Missing 'Server Name' in workitem" @{ workitem = $workitem.id }
        throw "Missing 'Server Name' in workitem" 
    }
    if (-not $fields.assignee) { 
        Log 'WARN' "Missing 'Assignee' in workitem" @{ workitem = $workitem.id }
        throw "Missing 'Assignee' in workitem" 
    }
    if (-not $fields.duration) { 
        $fields.duration = $DEFAULT_TTL_HOURS
        Log 'DEBUG' "Duration not present, defaulting" @{ workitem = $workitem.id; default = $fields.duration }
    }
    Log 'DEBUG' "Extracted custom fields" @{ workitem = $workitem.id; fields = $fields }
    return $fields
}

# ...existing code...
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
    Log 'INFO' "Handle-GrantAccess invoked" @{ workitem = $workitemId; project = $projectName; server = $server; assignee = $assigneeEmail; target = $targetUser }
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
        Log 'INFO' 'Access granted' @{ workitem = $workitemId; user = $dUser; role = $role; server = $server; durationH = $durationHours; expires = $expiresAt }
    } catch {
        Log 'ERROR' 'Grant failed' @{ workitem = $workitemId; err = $_.Exception.Message; stack = $_.Exception.StackTrace }
        Post-ZohoComment -workitemId $workitemId -message "Error granting access: $($_.Exception.Message)"
    }
}

function Handle-Revoke {
    param($workitemId, $workitem)
    Log 'INFO' "Handle-Revoke invoked" @{ workitem = $workitemId }
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
        Log 'ERROR' 'Revoke failed' @{ workitem = $workitemId; err = $_.Exception.Message; stack = $_.Exception.StackTrace }
        Post-ZohoComment -workitemId $workitemId -message "Error revoking access: $($_.Exception.Message)"
    }
}

# === MAIN WEBHOOK LISTENER ===
function Start-Listener {
    param([int]$port = 8090)
    $prefix = "http://localhost:$port/"
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
                $remote = $ctx.Request.RemoteEndPoint.ToString()
                $method = $req.HttpMethod
                $rawBody = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
                $bodyLen = if ($rawBody) { $rawBody.Length } else { 0 }
                # Redact headers for logs
                $hdrs = @{}
                foreach ($hk in $req.Headers.AllKeys) {
                    $val = $req.Headers[$hk]
                    if ($hk -match 'authorization|x-zoho-signature|cookie|set-cookie') { $val = 'REDACTED' }
                    $hdrs[$hk] = $val
                }
                Log 'DEBUG' "Incoming request" @{ remote = $remote; method = $method; url = $req.Url.ToString(); headers = $hdrs; body_length = $bodyLen }

                $receivedHmac = $req.Headers['X-Zoho-Signature']
                if ($receivedHmac) {
                    if (-not $env:HMAC_SECRET) {
                        Log 'WARN' "HMAC secret not set; cannot validate signature" @{ work = 'validation' }
                    } else {
                        try {
                            $hmacKey = [System.Text.Encoding]::UTF8.GetBytes($env:HMAC_SECRET)
                            $hashAlg = New-Object System.Security.Cryptography.HMACSHA256($hmacKey)
                            $calc = $hashAlg.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rawBody))
                            $calcB64 = [System.Convert]::ToBase64String($calc)
                            if ($calcB64 -ne $receivedHmac) { 
                                Log 'WARN' "HMAC mismatch" @{ expected = 'REDACTED'; received = 'REDACTED' }
                                $ctx.Response.StatusCode = 401; $ctx.Response.Close(); return 
                            } else {
                                Log 'DEBUG' "HMAC verified" @{ work = 'validation' }
                            }
                        } catch {
                            Log 'ERROR' "Error computing HMAC" @{ err = $_.Exception.Message }
                        }
                    }
                } else {
                    Log 'DEBUG' "No HMAC header present; skipping validation" @{}
                }

                $payloadRaw = $null
                try { $payloadRaw = $rawBody | ConvertFrom-Json } catch { Log 'WARN' "Failed to parse request JSON" @{ err = $_.Exception.Message; length = $bodyLen } ; $payloadRaw = $null }

                $eventType = if ($payloadRaw) { $payloadRaw.event } else { $null }
                $workitem = if ($payloadRaw) { $payloadRaw.data.workitem } else { $null }

                Log 'DEBUG' "Webhook event parsed" @{ event = $eventType; workitem_id = if ($workitem) { $workitem.id } else { $null } }

                if ($eventType -eq 'comment.added') {
                    $workitemId = $workitem.id
                    $projectName = $workitem.project.name
                    $assigneeEmail = $workitem.assignee.email
                    $fields = Extract-ChangeReleaseFields -workitem $workitem
                    $server   = $fields.server
                    $duration = $fields.duration
                    $target   = $fields.assignee
                    $lastComment = if ($workitem.comments -and $workitem.comments.Count -gt 0) { $workitem.comments[-1] } else { $null }
                    if ($lastComment) {
                        $text = $lastComment.comment_text.Trim()
                        Log 'DEBUG' "Last comment" @{ author = $lastComment.author.email; text = $text }
                        if ($text.ToLower() -eq 'approved') {
                            $author = $lastComment.author.email
                            if ($senior -contains $author) {
                                Log 'INFO' "Senior approval detected; granting access" @{ workitem = $workitemId; author = $author }
                                Handle-GrantAccess -workitemId $workitemId -projectName $projectName -assigneeEmail $assigneeEmail -ticketUrl $workitem.url -server $server -durationRaw $duration -targetUser $target
                            } else {
                                Log 'WARN' "Approval from non-senior; ignoring" @{ workitem = $workitemId; author = $author }
                            }
                        } else {
                            Log 'DEBUG' "Comment not an approval" @{ workitem = $workitemId; comment = $text }
                        }
                    } else {
                        Log 'DEBUG' "No comments present" @{ workitem = $workitemId }
                    }
                } elseif ($eventType -eq 'workitem.updated') {
                    $workitemId = $workitem.id
                    $status = $workitem.status
                    Log 'DEBUG' "Workitem updated" @{ workitem = $workitemId; status = $status }
                    if ($status -in @('Closed','Completed','Done')) {
                        Log 'INFO' "Workitem state indicates revoke" @{ workitem = $workitemId; status = $status }
                        Handle-Revoke -workitemId $workitemId -workitem $workitem
                    }
                } else {
                    Log 'DEBUG' "Unhandled event type" @{ event = $eventType }
                }

                $ctx.Response.StatusCode = 200
                $ctx.Response.Close()
            } catch {
                Log 'ERROR' "Listener job exception" @{ err = $_.Exception.Message; stack = $_.Exception.StackTrace }
                try { $ctx.Response.StatusCode = 500; $ctx.Response.Close() } catch {}
            }
        } | Out-Null
    }
}

Start-Listener -port $Port
# ...existing code...

# === MAIN WEBHOOK LISTENER ===
function Start-Listener {
    param([int]$port = 8090)
    $prefix = "http://localhost:$port/"
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
