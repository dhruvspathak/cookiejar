# ----------------------
# Utility / config
# ----------------------
Set-StrictMode -Version Latest

# Defaults (can be overridden via .env)
$portValue = 8090
if ($env:PORT -and [int]::TryParse($env:PORT, [ref]$portValue)) {
    $global:PORT = $portValue
}
else {
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
    }
    catch {
        $s = $obj.ToString()
    }
    # naive redaction rules
    $s = $s -replace '(?i)"(client_secret|secret|password|token|access_token|authorization)"\s*:\s*"[^\"]+"', '"$1":"[REDACTED]"'
    $s = $s -replace '(?i)(Authorization:\s*)Bearer\s+[A-Za-z0-9\-._~+/=]+', '$1REDACTED'
    return $s
}
function Log {
    param([Parameter(Mandatory = $true)]$Level, [Parameter(Mandatory = $true)]$Message, $Data = $null)
    $entry = @{
        timestamp = (Get-Date).ToString("o")
        level     = $Level
        message   = $Message
        data      = $Data
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
        workitemId   = $workitemId
        user         = $user
        role         = $role
        revokedAt    = $revokedAt
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
    <#
        Returns an Authorization header value: "Bearer <access_token>"

        Env / globals expected:
        - $global:DELINEA_API_BASE      # e.g. https://mytenant.delinea.app
        - $global:DELINEA_CLIENT_ID
        - $global:DELINEA_CLIENT_SECRET

        Optional:
        - $env:DELINEA_OAUTH_TOKEN  # cache token for this process if you want
    #>

    # Use cached token if one is already set (and you are ok ignoring expiry here)
    if ($env:DELINEA_OAUTH_TOKEN) {
        return "Bearer $($env:DELINEA_OAUTH_TOKEN)"
    }

    if (-not $global:DELINEA_API_BASE -or -not $global:DELINEA_CLIENT_ID -or -not $global:DELINEA_CLIENT_SECRET) {
        Log 'warn' "Delinea credentials not fully configured" @{
            hasApiBase   = [bool]$global:DELINEA_API_BASE
            hasClientId  = [bool]$global:DELINEA_CLIENT_ID
            hasClientSec = [bool]$global:DELINEA_CLIENT_SECRET
        } | Out-Null
        return $null
    }

    try {
        $tokenUri = "$($global:DELINEA_API_BASE.TrimEnd('/'))/identity/api/oauth2/token/xpmplatform"

        # client_credentials grant for headless integration
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $global:DELINEA_CLIENT_ID
            client_secret = $global:DELINEA_CLIENT_SECRET
            scope         = 'xpmheadless'
        }

        Write-Host "Requesting Delinea OAuth2 token from $tokenUri" -ForegroundColor Cyan

        $resp = Invoke-RestMethod -Uri $tokenUri `
                                  -Method Post `
                                  -Body $body `
                                  -ContentType 'application/x-www-form-urlencoded' `
                                  -ErrorAction Stop

        if (-not $resp.access_token) {
            Log 'error' "Delinea token response did not contain access_token" @{
                raw = $resp
            } | Out-Null
            return $null
        }

        $token = $resp.access_token

        # Optional: cache within this PowerShell process
        $env:DELINEA_OAUTH_TOKEN = $token

        Log 'info' "Delinea OAuth2 token obtained successfully" @{
            expires_in = $resp.expires_in
            scope      = $resp.scope
        } | Out-Null

        return "Bearer $token"
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host "Failed to authenticate with Delinea OAuth2: $msg" -ForegroundColor Red
        Log 'error' "Failed to authenticate with Delinea OAuth2" @{ error = $msg } | Out-Null
        return $null
    }
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
    }
    catch {
        Log 'error' "Failed to post comment to Zoho" @{ ticketId = $ticketId; error = $_.Exception.Message } | Out-Null
        return $false
    }
}

# ----------------------
# Delinea Privilege Escalation API helpers
# Implements the Privilege Elevation workflow from Delinea documentation:
# https://developer.delinea.com/docs/privilege-elevation
# ----------------------

function Invoke-DelineaPrivilegeEscalation {
    param(
        [string]$targetUser,
        [int]   $durationSeconds
    )
    <#
        Grants privilege elevation for a user via PrivilegeElevationCommand/AddAssignment.
        
        Returns: @{ success = $true/false; resp = ...; error = ... }
        
        NOTE: The exact JSON schema for AddAssignment varies by Delinea version.
        You must populate the $assignment hashtable with the correct field names
        (CommandId, PrincipalName, ScopeId, etc.) based on your tenant's API explorer.
    #>

    try {
        if (-not $global:DELINEA_API_BASE) {
            Log 'warn' "DELINEA_API_BASE not set; skipping privilege escalation (mock mode)" @{
                user     = $targetUser
                duration = $durationSeconds
            } | Out-Null
            return @{ success = $true; info = 'mocked' }
        }

        $authHeader = Get-DelineaToken
        if (-not $authHeader) {
            Log 'error' "Could not obtain Delinea authentication token" @{ user = $targetUser } | Out-Null
            return @{ success = $false; error = 'Authentication failed' }
        }

        $escalateUri = "$($global:DELINEA_API_BASE.TrimEnd('/'))/PrivilegeElevationCommand/AddAssignment"

        $headers = @{
            Authorization  = $authHeader
            'Content-Type' = 'application/json'
        }

        # TODO: map your Zoho / system model to Delinea PE fields.
        # You will fill these IDs from configuration / mapping:
        $nowUtc   = (Get-Date).ToUniversalTime()
        $expires  = $nowUtc.AddSeconds($durationSeconds)

        $assignment = @{
            # These names must be aligned with your tenant's API documentation.
            # Typical fields (names may differ by version):
            # CommandId     = '<PE command ID>'
            # PrincipalType = 'User'
            # PrincipalName = $targetUser  # or PrincipalId if you already resolved it
            # ScopeType     = 'System'
            # ScopeId       = '<system-id>'
            # Starts        = $nowUtc.ToString('o')
            # Expires       = $expires.ToString('o')
        }

        # Fail fast if you haven't wired this up yet:
        if ($assignment.Count -eq 0) {
            throw "PrivilegeElevationCommand/AddAssignment body not configured. Fill in CommandId / Principal / Scope etc."
        }

        $bodyJson = $assignment | ConvertTo-Json -Depth 5

        Write-Host "Invoking Delinea Privilege Elevation for '$targetUser' for $durationSeconds seconds" -ForegroundColor Cyan

        $resp = Invoke-RestMethod -Uri $escalateUri -Method Post -Headers $headers -Body $bodyJson -ErrorAction Stop

        Log 'info' "Delinea privilege escalation success" @{
            user     = $targetUser
            duration = $durationSeconds
            resp     = $resp
        } | Out-Null

        return @{ success = $true; resp = $resp }
    }
    catch {
        $err = $_.Exception

        # Example: if your tenant returns 409 for "already has assignment"
        if ($err -and $err.Response -and $err.Response.StatusCode.value__ -eq 409) {
            Log 'info' "Delinea privilege escalation already active" @{
                user     = $targetUser
                duration = $durationSeconds
            } | Out-Null
            return @{ success = $true; info = 'already-escalated' }
        }

        Write-Host "Delinea privilege escalation error: $($err.Message)" -ForegroundColor Red
        Log 'error' "Delinea privilege escalation failed" @{
            user     = $targetUser
            duration = $durationSeconds
            error    = $err.Message
        } | Out-Null

        return @{ success = $false; error = $err.Message }
    }
}

function Invoke-DelineaPrivilegeRevoke {
    param($targetUser)
    # Revoke privilege escalation for a user
    # Returns: @{ success = $true/false; resp = ...; error = ... }
    try {
        if (-not $global:DELINEA_API_BASE) { 
            Log 'warn' "DELINEA_API_BASE not set; skipping privilege revocation (mock/test mode)" @{ user = $targetUser } | Out-Null
            return @{ success = $true; info = "mocked" } 
        }
        
        # Get authenticated session token
        $token = Get-DelineaToken
        if (-not $token) {
            Log 'error' "Could not obtain Delinea authentication token for revocation" @{ user = $targetUser } | Out-Null
            return @{ success = $false; error = "Authentication failed" }
        }
        
        # Call privilege revocation endpoint
        $revokeUri = "$global:DELINEA_API_BASE/uprest/HandleAppClick?action=revoke"
        $headers = @{
            'Content-Type'  = 'application/json'
            'Authorization' = $token
        }
        
        $revokeBody = @{
            user   = $targetUser
            action = "revoke"
        } | ConvertTo-Json -Compress
        
        Write-Host "Revoking Delinea privilege escalation for user: $targetUser" -ForegroundColor Cyan
        $resp = Invoke-RestMethod -Uri $revokeUri -Method Post -Body $revokeBody -Headers $headers -ErrorAction Stop
        
        Log 'info' "Delinea privilege revocation success" @{ user = $targetUser; resp = $resp } | Out-Null
        return @{ success = $true; resp = $resp }
    }
    catch {
        # If privilege wasn't active (404 / not found) treat as success
        $err = $_.Exception
        if ($err -and $err.Response -and $err.Response.StatusCode -eq 404) {
            Log 'info' "Delinea privilege not active (treated as success)" @{ user = $targetUser } | Out-Null
            return @{ success = $true; info = "not-active" }
        }
        Log 'error' "Delinea privilege revocation failed" @{ user = $targetUser; error = $err.Message } | Out-Null
        return @{ success = $false; error = $err.Message }
    }
}

# Legacy grant/revoke wrappers (now call privilege escalation functions)
function Invoke-DelineaGrant {
    param($user, $role)
    # Legacy interface - now calls privilege escalation
    # $role parameter contains duration info if parsed from ticket
    $durationSeconds = if ($role -match '^\d+$') { [int]$role } else { 4 * 3600 }  # default 4 hours
    return Invoke-DelineaPrivilegeEscalation -targetUser $user -durationSeconds $durationSeconds
}

function Invoke-DelineaRevoke {
    param($user, $role)
    # Legacy interface - now calls privilege revocation
    return Invoke-DelineaPrivilegeRevoke -targetUser $user
}

# ----------------------
# Business helpers: parse ticket custom fields and map server->role
# ----------------------
function Extract-ChangeReleaseFields {
    param($ticket)
    # Returns a hashtable: server, duration (string), durationSeconds, targetUser, assigneeEmail
    $res = @{
        server          = $null
        duration        = $null
        durationSeconds = $null
        targetUser      = $null
        assigneeEmail   = $null
        workitemId      = $null
    }
    if ($ticket) {
        # Handle both hashtable and PSCustomObject from JSON conversion
        $ticketId = $null
        if ($ticket -is [System.Collections.IDictionary]) {
            $ticketId = $ticket['id']
        }
        elseif ($ticket.PSObject.Properties.Name -contains 'id') {
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
        }
        else {
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
        return ($h * 3600 + $m * 60 + $sec)
    }
    if ($s -match '^(\d+)\s*d') { return [int]$matches[1] * 24 * 3600 }
    if ($s -match '^(\d+)\s*h') { return [int]$matches[1] * 3600 }
    if ($s -match '^(\d+)\s*m') { return [int]$matches[1] * 60 }
    if ($s -match '^\d+$') { return [int]$s } # plain seconds
    # try TimeSpan parse
    try {
        $ts = [System.Xml.XmlConvert]::ToTimeSpan($s)  # supports PT.. as well
        return [int]$ts.TotalSeconds
    }
    catch {
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
        user       = $target
        role       = $role
        grantedAt  = $grantedAt
        expiresAt  = $expiresAt
        revokedAt  = $null
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
                            }
                            else {
                                Log 'error' "RevokeWorker: failed to revoke expired grant" @{ workitemId = $r.workitemId; user = $r.user; role = $r.role; error = $rev.error }
                            }
                        }
                    }
                }
            }
            catch {
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
        }
        catch {
            Log 'warn' "Failed to start ThreadJob for RevokeWorker; will run inline" $_.Exception.Message
        }
    }

    # fallback: start background job
    try {
        Start-Job -ArgumentList $global:REVOKE_WORKER_INTERVAL_SECONDS, $global:GRANTS_STORE -ScriptBlock $script | Out-Null
        Log 'info' "Started RevokeWorker using Start-Job (background process)" @{ intervalSeconds = $global:REVOKE_WORKER_INTERVAL_SECONDS }
        return
    }
    catch {
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
    }
    catch {
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
                    }
                    else {
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
                }
                else {
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
                    }
                    catch {
                        Write-Host "Grant access error: $($_.Exception.Message)" -ForegroundColor Red
                        throw
                    }
                }
                else {
                    Write-Host "Comment not an approval or author not approver; ignoring" -ForegroundColor Yellow
                }

                return @{ status = 200; body = "ok" }
            }
            elseif ($evt -eq 'workitem.updated' -or $evt -eq 'ticket.updated' -or $evt -eq 'workitem.state_changed') {
                # if the workitem status is in closed states, trigger revoke
                $status = $payload.ticket.status -as [string]
                $closedStates = @('Done', 'Closed', 'Completed', 'Resolved')
                if ($status -and $closedStates -contains $status) {
                    try {
                        Handle-Revoke -ticket $payload.ticket
                        Write-Host "Revoke processed successfully" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Revoke error: $($_.Exception.Message)" -ForegroundColor Red
                        throw
                    }
                }
                else {
                    Write-Host "Workitem updated but not closing; ignoring" -ForegroundColor Yellow
                }
                return @{ status = 200; body = "ok" }
            }
            else {
                Write-Host "Unhandled event type: $evt" -ForegroundColor Yellow
                return @{ status = 200; body = "ignored" }
            }
        }
        catch {
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
                HttpMethod     = $req.HttpMethod
                RawUrl         = $req.RawUrl
                RemoteEndPoint = $req.RemoteEndPoint.ToString()
                Headers        = $headers
                Body           = $body
            }

            # Create globals object to pass to handler
            $globalVars = [PSCustomObject]@{
                HMAC_REQUIRED    = $global:HMAC_REQUIRED
                HMAC_SECRET      = $global:HMAC_SECRET
                APPROVAL_REGEX   = $global:APPROVAL_REGEX
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
            }
            else {
                # Inline handling (process synchronously)
                try {
                    $result = & $handlerScript $requestObj $globalVars
                }
                catch {
                    Log 'error' "Handler script failed" $_.Exception.Message | Out-Null
                    $result = @{ status = 500; body = "handler-error" }
                }
                
                # Safely extract response values with defaults
                $respBody = "ok"
                $status = 200
                if ($result -is [hashtable]) {
                    if ($result.ContainsKey('body')) { $respBody = $result['body'] }
                    if ($result.ContainsKey('status')) { $status = $result['status'] }
                }
                elseif ($result -is [System.Management.Automation.PSCustomObject]) {
                    if ($result.PSObject.Properties.Name -contains 'body') { $respBody = $result.body }
                    if ($result.PSObject.Properties.Name -contains 'status') { $status = $result.status }
                }
                
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($respBody)
                $ctx.Response.ContentType = "text/plain"
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.StatusCode = $status
                $ctx.Response.OutputStream.Close()
            }

        }
        catch {
            Log 'error' "Listener exception" @{ error = $_.Exception.Message; line = $_.InvocationInfo.ScriptLineNumber } | Out-Null
            try {
                $ctx.Response.StatusCode = 500
                $error_response = "Internal server error"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($error_response)
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                $ctx.Response.OutputStream.Close()
            }
            catch {
                # If response fails, silently continue
            }
        }
    }
}

# ----------------------
# End of webhook.ps1
# ----------------------
