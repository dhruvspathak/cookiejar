# webhook.ps1
# Main webhook service for Zoho Sprints -> Delinea Secret Server integration.
# Features:
# - HTTP listener (port from $env:PORT; default 8090)
# - HMAC verification (X-Zoho-Signature) with HMAC_REQUIRED toggle
# - approval detection (configurable regex)
# - grants persistence (grants.jsonl) and revoke worker (auto TTL revoke)
# - Delinea & Zoho token handling (uses env values / mock endpoints)

# ----------------------
# Utility / config
# ----------------------
Set-StrictMode -Version Latest

# Defaults (can be overridden via .env)
$portValue = 8090
if ($env:PORT -and [int]::TryParse($env:PORT, [ref]$portValue)) {
    $global:PORT = $portValue
} else {
    $global:PORT = 8090
}
$global:HMAC_SECRET = $env:HMAC_SECRET
$global:HMAC_REQUIRED = if ($env:HMAC_REQUIRED) { [bool]::Parse($env:HMAC_REQUIRED) } else { $false }
$global:ZOHO_API_BASE = $env:ZOHO_API_BASE      # e.g. https://sprintsapi.zoho.com or http://localhost:9001 for mocks
$global:ZOHO_CLIENT_ID = $env:ZOHO_CLIENT_ID
$global:ZOHO_CLIENT_SECRET = $env:ZOHO_CLIENT_SECRET
$global:DELINEA_API_BASE = $env:DELINEA_API_BASE
$global:DELINEA_CLIENT_ID = $env:DELINEA_CLIENT_ID
$global:DELINEA_CLIENT_SECRET = $env:DELINEA_CLIENT_SECRET
$global:SENIOR_APPROVERS = if ($env:SENIOR_APPROVERS) { $env:SENIOR_APPROVERS -split ',' | ForEach-Object { $_.Trim().ToLower() } } else { @() }
$global:GRANTS_STORE = if ($env:GRANTS_STORE) { $env:GRANTS_STORE } else { Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) 'grants.jsonl' }
$global:APPROVAL_REGEX = if ($env:APPROVAL_REGEX) { $env:APPROVAL_REGEX } else { '^\s*(\/?approve|approved|approve|ack|ok|accepted|✅|\u2705)\b' }
$global:REVOKE_WORKER_INTERVAL_SECONDS = if ($env:REVOKE_WORKER_INTERVAL_SECONDS) { [int]$env:REVOKE_WORKER_INTERVAL_SECONDS } else { 60 }

# Simple log function - outputs JSON lines. Redacts obvious secrets.
function Redact-ForLog {
    param($obj)
    try {
        $s = $obj | ConvertTo-Json -Depth 6 -Compress
    } catch {
        $s = $obj.ToString()
    }
    # naive redaction rules
    $s = $s -replace '(?i)"(client_secret|secret|password|token|access_token|authorization)"\s*:\s*"[^\"]+"', '"$1":"[REDACTED]"'
    $s = $s -replace '(?i)(Authorization:\s*)Bearer\s+[A-Za-z0-9\-._~+/=]+', '$1REDACTED'
    return $s
}
function Log {
    param([Parameter(Mandatory=$true)]$Level, [Parameter(Mandatory=$true)]$Message, $Data = $null)
    $entry = @{
        timestamp = (Get-Date).ToString("o")
        level = $Level
        message = $Message
        data = $Data
    }
    Write-Output (Redact-ForLog $entry)
}

# ----------------------
# HMAC signature helper
# ----------------------
function New-ZohoSignature {
    param($body, $secret)
    if (-not $secret) { return $null }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($secret)
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
    return [Convert]::ToBase64String($hash)
}

# ----------------------
# Grants store helpers (JSON-lines)
# Each record: { workitemId, user, role, expiresAt (ISO), grantedAt (ISO), revokedAt (ISO|null), revokeReason }
# ----------------------
function Append-GrantRecord {
    param($rec)
    $line = $rec | ConvertTo-Json -Compress
    $line | Out-File -FilePath $global:GRANTS_STORE -Append -Encoding utf8
}
function Read-AllGrantRecords {
    if (-not (Test-Path $global:GRANTS_STORE)) { return @() }
    Get-Content $global:GRANTS_STORE | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json }
}
function Find-ActiveGrant {
    param($workitemId, $user, $role)
    $all = Read-AllGrantRecords
    foreach ($r in $all) {
        if ($r.workitemId -eq $workitemId -and $r.user -eq $user -and $r.role -eq $role -and (-not $r.revokedAt)) {
            return $r
        }
    }
    return $null
}
function Mark-GrantRevoked {
    param($workitemId, $user, $role, $revokedAt, $reason)
    # Append a revocation record (simple append-only audit).
    $rec = @{
        workitemId = $workitemId
        user = $user
        role = $role
        revokedAt = $revokedAt
        revokeReason = $reason
    }
    Append-GrantRecord $rec
}

# ----------------------
# Token helpers (very simple, mostly for real endpoints; in mocks these env endpoints can be plain)
# These functions try to return a token string if possible. If ZOHO_API_BASE or DELINEA_API_BASE are http://localhost mocks
# that accept no auth, the functions will return $null and the caller will still attempt calls without Authorization header.
# ----------------------
function Get-ZohoToken {
    # In production you would implement full OAuth refresh or client cred flows.
    # For many Zoho APIs you can use Server-based OAuth or permanent tokens; for test/mocks allow env override ZOHO_OAUTH_TOKEN.
    if ($env:ZOHO_OAUTH_TOKEN) { return $env:ZOHO_OAUTH_TOKEN }
    # Attempt client credentials (if endpoint supports it). Otherwise return $null.
    return $null
}
function Get-DelineaToken {
    if ($env:DELINEA_OAUTH_TOKEN) { return $env:DELINEA_OAUTH_TOKEN }
    # Optionally support client credentials flow if available on your Delinea instance.
    return $null
}

# ----------------------
# Zoho comment posting helper
# ----------------------
function Post-ZohoComment {
    param($ticketId, $commentText)
    try {
        if (-not $global:ZOHO_API_BASE) { 
            Log 'warn' "ZOHO_API_BASE not configured, skipping Post-ZohoComment" @{ ticketId = $ticketId; comment = $commentText } | Out-Null
            return $true 
        }
        $uri = [Uri]::EscapeUriString("$global:ZOHO_API_BASE/sprints/v1/tickets/$ticketId/comments")
        $body = @{ text = $commentText } | ConvertTo-Json -Compress
        $headers = @{ 'Content-Type' = 'application/json' }
        $token = Get-ZohoToken
        if ($token) { $headers['Authorization'] = "Zoho-oauthtoken $token" }
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers -ErrorAction Stop
        Log 'info' "Posted comment to Zoho" @{ ticketId = $ticketId; resp = $resp } | Out-Null
        return $true
    } catch {
        Log 'error' "Failed to post comment to Zoho" @{ ticketId = $ticketId; error = $_.Exception.Message } | Out-Null
        return $false
    }
}

# ----------------------
# Delinea grant/revoke helpers (simple REST wrappers)
# ----------------------
function Invoke-DelineaGrant {
    param($user, $role)
    try {
        if (-not $global:DELINEA_API_BASE) { 
            Log 'warn' "DELINEA_API_BASE not set; skipping real grant (mock/test mode)" @{ user = $user; role = $role } | Out-Null
            return @{ success = $true; info = "mocked" } 
        }
        $uri = [Uri]::EscapeUriString("$global:DELINEA_API_BASE/api/roleAssignments")
        $body = @{ user = $user; role = $role } | ConvertTo-Json -Compress
        $headers = @{ 'Content-Type' = 'application/json' }
        $token = Get-DelineaToken
        if ($token) { $headers['Authorization'] = "Bearer $token" }
        Write-Host "Invoking Delinea API: $uri" -ForegroundColor Cyan
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers -ErrorAction Stop
        Write-Host "Delinea response: $($resp | ConvertTo-Json)" -ForegroundColor Cyan
        Log 'info' "Delinea grant response" @{ user = $user; role = $role; resp = $resp } | Out-Null
        return @{ success = $true; resp = $resp }
    } catch {
        # classify common idempotent cases (e.g., 409) as success
        $err = $_.Exception
        if ($err -and $err.Response -and $err.Response.StatusCode -eq 409) {
            Log 'info' "Delinea grant already exists (treated as success)" @{ user = $user; role = $role } | Out-Null
            return @{ success = $true; info = "already-assigned" }
        }
        Write-Host "Delinea grant error: $($err.Message)" -ForegroundColor Red
        Log 'error' "Delinea grant failed" @{ user = $user; role = $role; error = $err.Message } | Out-Null
        return @{ success = $false; error = $err.Message }
    }
}
function Invoke-DelineaRevoke {
    param($user, $role)
    try {
        if (-not $global:DELINEA_API_BASE) { 
            Log 'warn' "DELINEA_API_BASE not set; skipping real revoke (mock/test mode)" @{ user = $user; role = $role } | Out-Null
            return @{ success = $true; info = "mocked" } 
        }
        # This assumes Delinea exposes a DELETE or POST revoke endpoint; adapt as needed.
        $uri = [Uri]::EscapeUriString("$global:DELINEA_API_BASE/api/roleAssignments/revoke")
        $body = @{ user = $user; role = $role } | ConvertTo-Json -Compress
        $headers = @{ 'Content-Type' = 'application/json' }
        $token = Get-DelineaToken
        if ($token) { $headers['Authorization'] = "Bearer $token" }
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers -ErrorAction Stop
        Log 'info' "Delinea revoke response" @{ user = $user; role = $role; resp = $resp } | Out-Null
        return @{ success = $true; resp = $resp }
    } catch {
        # If role wasn't present (404 / not found) treat as success
        $err = $_.Exception
        if ($err -and $err.Response -and $err.Response.StatusCode -eq 404) {
            Log 'info' "Delinea revoke - role not present (treated as success)" @{ user = $user; role = $role } | Out-Null
            return @{ success = $true; info = "not-present" }
        }
        Log 'error' "Delinea revoke failed" @{ user = $user; role = $role; error = $err.Message } | Out-Null
        return @{ success = $false; error = $err.Message }
    }
}

# ----------------------
# Business helpers: parse ticket custom fields and map server->role
# ----------------------
function Extract-ChangeReleaseFields {
    param($ticket)
    # Returns a hashtable: server, duration (string), durationSeconds, targetUser, assigneeEmail
    $res = @{
        server = $null
        duration = $null
        durationSeconds = $null
        targetUser = $null
        assigneeEmail = $null
        workitemId = $null
    }
    if ($ticket) {
        # Handle both hashtable and PSCustomObject from JSON conversion
        $ticketId = $null
        if ($ticket -is [System.Collections.IDictionary]) {
            $ticketId = $ticket['id']
        } elseif ($ticket.PSObject.Properties.Name -contains 'id') {
            $ticketId = $ticket.id
        }
        if ($ticketId) { $res.workitemId = $ticketId }
        # customFields may be array of {name, value} objects
        if ($ticket.customFields -and $ticket.customFields.Count -gt 0) {
            foreach ($f in $ticket.customFields) {
                if ($f.name -and $f.value) {
                    $name = ($f.name).ToString().ToLower()
                    $val = $f.value
                    switch -Wildcard ($name) {
                        '*server*' { if (-not $res.server) { $res.server = $val } }
                        '*duration*' { if (-not $res.duration) { $res.duration = $val } }
                        '*target*' { if (-not $res.targetUser) { $res.targetUser = $val } }
                    }
                }
            }
        }
        # fallback to top-level fields
        if (-not $res.targetUser -and $ticket.assignee -and $ticket.assignee.email) { $res.assigneeEmail = $ticket.assignee.email }
        if (-not $res.targetUser -and $ticket.assignee -and $ticket.assignee.username) { $res.assigneeEmail = $ticket.assignee.username }
        if ($res.targetUser -and -not $res.assigneeEmail) { $res.assigneeEmail = $res.targetUser }
        # parse duration to seconds (supports '2h', '30m', '1d', 'PT1H' etc.)
        if ($res.duration) {
            $parsed = Parse-DurationToSeconds -durationStr $res.duration
            $res.durationSeconds = $parsed
        } else {
            # default to 4 hours if unspecified
            $res.durationSeconds = 4 * 3600
        }
    }
    return $res
}

function Parse-DurationToSeconds {
    param($durationStr)
    if (-not $durationStr) { return 0 }
    $s = $durationStr.Trim()
    # ISO8601 PTnHnMnS support
    if ($s -match '^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$') {
        $h = if ($matches[1]) { [int]$matches[1] } else { 0 }
        $m = if ($matches[2]) { [int]$matches[2] } else { 0 }
        $sec = if ($matches[3]) { [int]$matches[3] } else { 0 }
        return ($h*3600 + $m*60 + $sec)
    }
    if ($s -match '^(\d+)\s*d') { return [int]$matches[1] * 24 * 3600 }
    if ($s -match '^(\d+)\s*h') { return [int]$matches[1] * 3600 }
    if ($s -match '^(\d+)\s*m') { return [int]$matches[1] * 60 }
    if ($s -match '^\d+$') { return [int]$s } # plain seconds
    # try TimeSpan parse
    try {
        $ts = [System.Xml.XmlConvert]::ToTimeSpan($s)  # supports PT.. as well
        return [int]$ts.TotalSeconds
    } catch {
        # fallback default 4 hours
        return 4 * 3600
    }
}

function Get-RoleForServer {
    param($server)
    # Simple mapping: override as needed. For demo, transform server name into a role string.
    if (-not $server) { return $null }
    # Example mapping rule: server 'prod-app-server-01' => 'role_prod_app_server_01'
    $r = $server -replace '[^A-Za-z0-9]', '_' -replace '__+', '_'
    return "role_$($r.ToLower())"
}

# ----------------------
# High-level handlers: grant and revoke
# ----------------------
function Handle-GrantAccess {
    param($ticket, $comment)
    $fields = Extract-ChangeReleaseFields -ticket $ticket
    $workitemId = $fields.workitemId
    $target = if ($fields.targetUser) { $fields.targetUser } else { $fields.assigneeEmail }
    if (-not $target) {
        Log 'error' "No target user found for grant" @{ workitemId = $workitemId; fields = $fields } | Out-Null
        Post-ZohoComment -ticketId $workitemId -commentText "Grant failed: could not determine target user." | Out-Null
        return
    }
    $role = Get-RoleForServer -server $fields.server
    if (-not $role) {
        Log 'error' "No role mapping found for server" @{ server = $fields.server; workitemId = $workitemId } | Out-Null
        Post-ZohoComment -ticketId $workitemId -commentText "Grant failed: could not map server '$($fields.server)' to a role." | Out-Null
        return
    }
    # idempotency check: if active grant exists for same workitem/user/role skip actual grant
    $existing = Find-ActiveGrant -workitemId $workitemId -user $target -role $role
    if ($existing) {
        Log 'info' "Active grant already exists; skipping grant" @{ workitemId = $workitemId; user = $target; role = $role } | Out-Null
        Post-ZohoComment -ticketId $workitemId -commentText "Grant already exists for $target on role $role (idempotent). Expires: $($existing.expiresAt)"
        return
    }

    # Perform grant via Delinea API
    Write-Host "Calling Invoke-DelineaGrant for user=$target, role=$role" -ForegroundColor Cyan
    $grantResp = Invoke-DelineaGrant -user $target -role $role
    Write-Host "Grant response type: $($grantResp.GetType().Name), value: $($grantResp | ConvertTo-Json)" -ForegroundColor Cyan
    if ($null -eq $grantResp -or -not $grantResp.success) {
        $errMsg = if ($null -eq $grantResp) { "Grant call failed (null response)" } else { $grantResp.error }
        $msg = "Grant failed for $target -> $role`: $errMsg"
        Post-ZohoComment -ticketId $workitemId -commentText $msg
        return
    }

    $grantedAt = (Get-Date).ToUniversalTime().ToString("o")
    $expiresAt = (Get-Date).ToUniversalTime().AddSeconds($fields.durationSeconds).ToString("o")
    $rec = @{
        workitemId = $workitemId
        user = $target
        role = $role
        grantedAt = $grantedAt
        expiresAt = $expiresAt
        revokedAt = $null
    }
    Append-GrantRecord $rec

    Log 'info' "Access granted and persisted" @{ workitemId = $workitemId; user = $target; role = $role; expiresAt = $expiresAt } | Out-Null
    Post-ZohoComment -ticketId $workitemId -commentText "Access GRANTED to $target on server $($fields.server) (role: $role). Expires at $expiresAt (UTC). Granted by approval comment: '$($comment.text)'." | Out-Null
}

function Handle-Revoke {
    param($ticket)
    $fields = Extract-ChangeReleaseFields -ticket $ticket
    $workitemId = $fields.workitemId
    $target = if ($fields.targetUser) { $fields.targetUser } else { $fields.assigneeEmail }
    if (-not $target) {
        Log 'error' "No target user found for revoke" @{ workitemId = $workitemId; fields = $fields } | Out-Null
        Post-ZohoComment -ticketId $workitemId -commentText "Revoke failed: could not determine target user." | Out-Null
        return
    }
    $role = Get-RoleForServer -server $fields.server
    if (-not $role) {
        Log 'error' "No role mapping found for server during revoke" @{ server = $fields.server; workitemId = $workitemId } | Out-Null
        Post-ZohoComment -ticketId $workitemId -commentText "Revoke failed: could not map server '$($fields.server)' to a role." | Out-Null
        return
    }

    # call Delinea revoke - idempotent handling inside
    $revokeResp = Invoke-DelineaRevoke -user $target -role $role
    if (-not $revokeResp.success) {
        $msg = "Revoke failed for $target -> $role`: $($revokeResp.error)"
        Post-ZohoComment -ticketId $workitemId -commentText $msg | Out-Null
        return
    }

    $revokedAt = (Get-Date).ToUniversalTime().ToString("o")
    Mark-GrantRevoked -workitemId $workitemId -user $target -role $role -revokedAt $revokedAt -reason "workitem-closed"
    Log 'info' "Access revoked" @{ workitemId = $workitemId; user = $target; role = $role; revokedAt = $revokedAt } | Out-Null
    Post-ZohoComment -ticketId $workitemId -commentText "Access REVOKED for $target on server $($fields.server) (role: $role). Revoked at $revokedAt (UTC)." | Out-Null
}

# ----------------------
# Revoke worker: periodically looks for expired grants and revokes them
# ----------------------
function Start-RevokeWorker {
    # spawn a thread job if available, else background job, else run in the process
    $script = {
        param($intervalSeconds, $grantsStorePath)
        while ($true) {
            try {
                $now = (Get-Date).ToUniversalTime()
                $recs = @()
                if (Test-Path $grantsStorePath) {
                    $recs = Get-Content $grantsStorePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json }
                }
                foreach ($r in $recs) {
                    # consider only records that have expiresAt and are not revoked (no revokedAt or null)
                    if ($r.expiresAt -and (-not $r.revokedAt)) {
                        $exp = [datetime]::Parse($r.expiresAt)
                        if ($exp -le $now) {
                            # revoke: call Delinea and append revocation
                            Log 'info' "RevokeWorker: revoking expired grant" @{ workitemId = $r.workitemId; user = $r.user; role = $r.role; expiresAt = $r.expiresAt }
                            $rev = Invoke-DelineaRevoke -user $r.user -role $r.role
                            if ($rev.success) {
                                $revokedAt = (Get-Date).ToUniversalTime().ToString("o")
                                Mark-GrantRevoked -workitemId $r.workitemId -user $r.user -role $r.role -revokedAt $revokedAt -reason "ttl-expired"
                                # Post comment to Zoho to inform ticket
                                Post-ZohoComment -ticketId $r.workitemId -commentText "Access automatically REVOKED (TTL expired) for $($r.user) on role $($r.role). Expired at $($r.expiresAt) (UTC)."
                            } else {
                                Log 'error' "RevokeWorker: failed to revoke expired grant" @{ workitemId = $r.workitemId; user = $r.user; role = $r.role; error = $rev.error }
                            }
                        }
                    }
                }
            } catch {
                Log 'error' "RevokeWorker exception" $_.Exception.Message
            }
            Start-Sleep -Seconds $intervalSeconds
        }
    }

    # Start thread job if available (preferred)
    if (Get-Module -ListAvailable -Name ThreadJob) {
        try {
            Import-Module ThreadJob -ErrorAction Stop
            Start-ThreadJob -ArgumentList $global:REVOKE_WORKER_INTERVAL_SECONDS, $global:GRANTS_STORE -ScriptBlock $script | Out-Null
            Log 'info' "Started RevokeWorker using Start-ThreadJob" @{ intervalSeconds = $global:REVOKE_WORKER_INTERVAL_SECONDS }
            return
        } catch {
            Log 'warn' "Failed to start ThreadJob for RevokeWorker; will run inline" $_.Exception.Message
        }
    }

    # fallback: start background job
    try {
        Start-Job -ArgumentList $global:REVOKE_WORKER_INTERVAL_SECONDS, $global:GRANTS_STORE -ScriptBlock $script | Out-Null
        Log 'info' "Started RevokeWorker using Start-Job (background process)" @{ intervalSeconds = $global:REVOKE_WORKER_INTERVAL_SECONDS }
        return
    } catch {
        Log 'warn' "Failed to start background job for RevokeWorker; running in-process (blocking) - not ideal for production." $_.Exception.Message
        # last fallback: run in runspace (non-blocking is hard) - run in a separate thread using .NET Thread
        $thread = [System.Threading.Thread]::new({
            & $script $global:REVOKE_WORKER_INTERVAL_SECONDS $global:GRANTS_STORE
        })
        $thread.IsBackground = $true
        $thread.Start()
        Log 'info' "Started RevokeWorker on raw .NET thread (fallback)"
    }
}

# ----------------------
# Listener and request processing
# ----------------------
function Start-Listener {
    Log 'info' "Starting HTTP listener" @{ port = $global:PORT }
    $listener = [System.Net.HttpListener]::new()
    $prefix = "http://127.0.0.1:{0}/" -f $global:PORT
    $listener.Prefixes.Add($prefix)
    try {
        $listener.Start()
    } catch {
        Log 'error' "Failed to start listener - maybe port in use or insufficient privileges" $_.Exception.Message
        throw
    }
    Log 'info' "Listening for incoming webhooks" @{ prefix = $prefix }

    # Determine if ThreadJob is available for per-request background processing
    $useThreadJob = $false
    if (Get-Module -ListAvailable -Name ThreadJob) {
        try { Import-Module ThreadJob -ErrorAction Stop; $useThreadJob = $true } catch { $useThreadJob = $false }
    }

    # Define handler script once, outside the loop
    $handlerScript = {
        param($requestObj, $globalVars)
        # Handler script - runs in same process (inline) or ThreadJob context
        # All functions are accessible via module context in ThreadJob, or directly in inline
        try {
            $headers = $requestObj.Headers
            $body = $requestObj.Body
            # HMAC validation
            $sigHeader = $null
            if ($headers.ContainsKey('X-Zoho-Signature')) { $sigHeader = $headers['X-Zoho-Signature'] } elseif ($headers.ContainsKey('x-zoho-signature')) { $sigHeader = $headers['x-zoho-signature'] }
            $hmacRequired = [bool]$globalVars.HMAC_REQUIRED
            $hmacSecret = $globalVars.HMAC_SECRET
            
            if ($hmacRequired -and -not $sigHeader) {
                Write-Host "HMAC validation failed: Missing signature" -ForegroundColor Yellow
                return @{ status = 401; body = "Missing signature" }
            }
            if ($sigHeader -and $hmacSecret) {
                # Call New-ZohoSignature - this works in same-process inline and ThreadJob
                $computed = New-ZohoSignature -body $body -secret $hmacSecret
                if ($computed -ne $sigHeader) {
                    if ($hmacRequired) {
                        Write-Host "HMAC validation failed: Invalid signature" -ForegroundColor Yellow
                        return @{ status = 401; body = "Invalid signature" }
                    } else {
                        Write-Host "HMAC validation: Signature mismatch but HMAC_REQUIRED=false, continuing" -ForegroundColor Yellow
                    }
                }
            }

            # parse JSON
            $payload = $null
            try { $payload = $body | ConvertFrom-Json -ErrorAction Stop } catch { $payload = $null }
            if (-not $payload) {
                Write-Host "Invalid JSON or empty body" -ForegroundColor Yellow
                return @{ status = 400; body = "Bad JSON" }
            }

            # Decision logic: event types - 'comment.added' or workitem status change
            $evt = $payload.event
            Write-Host "Received event: $evt" -ForegroundColor Cyan

            if ($evt -eq 'comment.added') {
                # get last comment payload (support payload.comment or payload.comments array)
                $comment = $payload.comment
                if (-not $comment -and $payload.comments) { $comment = $payload.comments[-1] }
                if (-not $comment) { 
                    Write-Host "No comment object found" -ForegroundColor Yellow
                    return @{ status = 200; body = "ignored" } 
                }

                $text = ($comment.text -as [string])
                if (-not $text) { $text = '' }
                
                $authorEmail = ($comment.author.email -as [string])
                if (-not $authorEmail) { $authorEmail = ($comment.author.userEmail -as [string]) }
                if (-not $authorEmail) { $authorEmail = '' }
                # approval detection using regex
                $approvalRegex = $globalVars.APPROVAL_REGEX
                if ($approvalRegex) {
                    $regex = [regex]::new($approvalRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    $isApproval = $regex.IsMatch($text)
                } else {
                    $isApproval = $false
                }
                $isApprover = $false
                if ($authorEmail -and $globalVars.SENIOR_APPROVERS) {
                    $isApprover = $globalVars.SENIOR_APPROVERS -contains $authorEmail.ToLower()
                }
                Write-Host "Comment: approval=$isApproval, approver=$isApprover, author=$authorEmail" -ForegroundColor Cyan

                if ($isApproval -and $isApprover) {
                    try {
                        Handle-GrantAccess -ticket $payload.ticket -comment $comment
                        Write-Host "Grant access processed successfully" -ForegroundColor Green
                    } catch {
                        Write-Host "Grant access error: $($_.Exception.Message)" -ForegroundColor Red
                        throw
                    }
                } else {
                    Write-Host "Comment not an approval or author not approver; ignoring" -ForegroundColor Yellow
                }

                return @{ status = 200; body = "ok" }
            } elseif ($evt -eq 'workitem.updated' -or $evt -eq 'ticket.updated' -or $evt -eq 'workitem.state_changed') {
                # if the workitem status is in closed states, trigger revoke
                $status = $payload.ticket.status -as [string]
                $closedStates = @('Done','Closed','Completed','Resolved')
                if ($status -and $closedStates -contains $status) {
                    try {
                        Handle-Revoke -ticket $payload.ticket
                        Write-Host "Revoke processed successfully" -ForegroundColor Green
                    } catch {
                        Write-Host "Revoke error: $($_.Exception.Message)" -ForegroundColor Red
                        throw
                    }
                } else {
                    Write-Host "Workitem updated but not closing; ignoring" -ForegroundColor Yellow
                }
                return @{ status = 200; body = "ok" }
            } else {
                Write-Host "Unhandled event type: $evt" -ForegroundColor Yellow
                return @{ status = 200; body = "ignored" }
            }
        } catch {
            Write-Host "Handler error: $($_.Exception.Message)" -ForegroundColor Red
            return @{ status = 500; body = "handler-error" }
        }
    }

    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
            # Read body synchronously (we capture everything we need)
            $req = $ctx.Request
            $body = ''
            if ($req.HasEntityBody) {
                $sr = New-Object System.IO.StreamReader($req.InputStream)
                $body = $sr.ReadToEnd()
                $sr.Close()
            }
            $headers = @{}
            foreach ($key in $req.Headers.AllKeys) { $headers[$key] = $req.Headers[$key] }

            # Build a lightweight PSCustomObject to pass to handler (serializable)
            $requestObj = [PSCustomObject]@{
                HttpMethod = $req.HttpMethod
                RawUrl = $req.RawUrl
                RemoteEndPoint = $req.RemoteEndPoint.ToString()
                Headers = $headers
                Body = $body
            }

            # Create globals object to pass to handler
            $globalVars = [PSCustomObject]@{
                HMAC_REQUIRED = $global:HMAC_REQUIRED
                HMAC_SECRET = $global:HMAC_SECRET
                APPROVAL_REGEX = $global:APPROVAL_REGEX
                SENIOR_APPROVERS = $global:SENIOR_APPROVERS
            }

            # Dispatch: either background threadjob or handle inline (safe)
            if ($useThreadJob) {
                # ThreadJob shares process memory so functions are accessible
                Start-ThreadJob -ArgumentList $requestObj, $globalVars -ScriptBlock $handlerScript | Out-Null
                # Respond quickly to the client that request is accepted
                $responseBody = "accepted"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
                $ctx.Response.ContentType = "text/plain"
                $ctx.Response.ContentLength64 = $buffer.Length
                $ctx.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                $ctx.Response.StatusCode = 202
                $ctx.Response.OutputStream.Close()
            } else {
                # Inline handling (process synchronously)
                $result = & $handlerScript $requestObj $globalVars
                $respBody = $result.body
                $status = if ($result.status) { $result.status } else { 200 }
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($respBody)
                $ctx.Response.ContentType = "text/plain"
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.StatusCode = $status
                $ctx.Response.OutputStream.Close()
            }

        } catch {
            Log 'error' "Listener exception" $_.Exception.Message
        }
    }
}

# ----------------------
# End of webhook.ps1
# ----------------------
