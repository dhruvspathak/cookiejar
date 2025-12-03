# Delinea Privilege Escalation Integration Guide

## Overview

This webhook service now implements the **Delinea Privilege Escalation API** to grant and revoke temporary elevated privileges to users. The system integrates with the Delinea Cloud Suite/PAS (Privileged Access Service) using the official Privilege Elevation workflow.

## Architecture

```
Zoho Sprints (Webhook Event)
    ↓
CookieJar Webhook Service (Port 9090)
    ↓ [HMAC Validation]
    ↓
Approval Detection (Regex Match)
    ↓ [Senior Approver Check]
    ↓
Delinea Authentication (OAuth)
    ├─ /Security/StartChallenge
    ├─ /Security/AdvanceAuthentication
    └─ Returns Bearer Token
    ↓
Delinea Privilege Escalation
    ├─ /uprest/HandleAppClick [Escalate]
    └─ /uprest/HandleAppClick?action=revoke [Revoke]
    ↓
Grant Record Audit Log (grants.jsonl)
    ↓ [TTL Check]
    ↓
Auto-Revoke Worker
```

## Authentication Flow

### Step 1: Start Challenge
When the webhook needs to escalate privileges, it initiates an authentication challenge:

```
POST /Security/StartChallenge
{
  "TenantId": "",
  "User": "<DELINEA_CLIENT_ID>",
  "Version": "1.0",
  "AssociatedEntityType": "API",
  "AssociatedEntityName": "CookieJar"
}
```

**Response:**
```json
{
  "success": true,
  "Result": {
    "SessionId": "T0zrHgE6kkKdj...",
    "TenantId": "AAA0004",
    "Challenges": [{
      "Mechanisms": [{
        "MechanismId": "Wdf7j9cqyu6Ymo...",
        "Name": "EMAIL",
        ...
      }]
    }],
    ...
  }
}
```

### Step 2: Advance Authentication
The client secret is submitted to advance the authentication:

```
POST /Security/AdvanceAuthentication
{
  "TenantId": "AAA0004",
  "SessionId": "T0zrHgE6kkKdjs...",
  "MechanismId": "Wdf7j9cqyu6Ymoq...",
  "Answer": "<DELINEA_CLIENT_SECRET>",
  "Action": "Answer"
}
```

**Response:**
```json
{
  "success": true,
  "Result": {
    "Auth": "DE01F612EC5B81DD05E...",
    "User": "dhruvap@cookiejar",
    "AuthLevel": "High",
    "UserId": "abcd1234-b5f5-4995-a500-70859b6adbf7",
    "Summary": "LoginSuccess",
    ...
  }
}
```

The `Auth` field is the bearer token used for subsequent API calls.

### Step 3: Privilege Escalation
With the bearer token, escalate the user's privilege level:

```
POST /uprest/HandleAppClick
Authorization: Bearer <Auth_Token>
{
  "user": "<target_user>",
  "durationSeconds": 14400,
  "requestType": "privilege_escalation"
}
```

### Step 4: Privilege Revocation
When the TTL expires or is manually revoked:

```
POST /uprest/HandleAppClick?action=revoke
Authorization: Bearer <Auth_Token>
{
  "user": "<target_user>",
  "action": "revoke"
}
```

## Configuration

### Required Environment Variables

```env
# Delinea API endpoint
DELINEA_API_BASE=https://cookiejar.delinea.app

# OAuth credentials (obtained from Delinea tenant)
DELINEA_CLIENT_ID=dhruvap@cookiejar
DELINEA_CLIENT_SECRET=GoldGreen@21

# Optional: Pre-generated token (if available)
DELINEA_OAUTH_TOKEN=<bearer_token>
```

### Optional Overrides

```env
# Approval keyword detection
APPROVAL_REGEX=^\s*(\/?approve|approved|ack|ok|accepted|✅)\b

# Senior approvers (comma-separated emails)
SENIOR_APPROVERS=alice@example.com,bob@example.com

# Grant revocation check interval (seconds)
REVOKE_WORKER_INTERVAL_SECONDS=60
```

## Implementation Details

### Authentication Function: `Get-DelineaToken`

Located in `webhook.ps1`, this function handles the complete OAuth flow:

1. **Validates Credentials**: Checks if `DELINEA_API_BASE`, `DELINEA_CLIENT_ID`, and `DELINEA_CLIENT_SECRET` are configured
2. **Initiates Challenge**: Calls `/Security/StartChallenge` with client credentials
3. **Advances Authentication**: Submits the client secret via `/Security/AdvanceAuthentication`
4. **Returns Bearer Token**: Extracts and returns the `Auth` field from the response
5. **Error Handling**: Logs failures and returns `$null` if authentication fails

**Code Location:** Lines 109-165 in `webhook.ps1`

### Privilege Escalation Functions

#### `Invoke-DelineaPrivilegeEscalation`
- **Purpose**: Grant temporary elevated privileges to a user
- **Parameters**: 
  - `$targetUser`: User to escalate (email or username)
  - `$durationSeconds`: Duration of privilege (e.g., 14400 for 4 hours)
- **Returns**: `@{ success = $true/false; resp = ...; error = ... }`
- **Location**: Lines 249-297 in `webhook.ps1`

#### `Invoke-DelineaPrivilegeRevoke`
- **Purpose**: Revoke privilege escalation for a user
- **Parameters**:
  - `$targetUser`: User to revoke
- **Returns**: `@{ success = $true/false; resp = ...; error = ... }`
- **Location**: Lines 299-334 in `webhook.ps1`

#### Legacy Wrappers
For backward compatibility, `Invoke-DelineaGrant` and `Invoke-DelineaRevoke` now delegate to the privilege escalation functions:

```powershell
function Invoke-DelineaGrant {
    param($user, $role)
    # Parse duration from $role parameter (or use default 4 hours)
    $durationSeconds = if ($role -match '^\d+$') { [int]$role } else { 4 * 3600 }
    return Invoke-DelineaPrivilegeEscalation -targetUser $user -durationSeconds $durationSeconds
}

function Invoke-DelineaRevoke {
    param($user, $role)
    return Invoke-DelineaPrivilegeRevoke -targetUser $user
}
```

**Location**: Lines 336-347 in `webhook.ps1`

## Workflow: Approval to Escalation

### 1. Webhook Receives Event
```json
{
  "ticket": {
    "id": "12345",
    "customFields": [
      { "name": "Server", "value": "prod-app-01" },
      { "name": "Duration", "value": "2h" }
    ],
    "assignee": { "email": "dev@company.com" }
  },
  "comment": {
    "text": "/approve",
    "author": { "email": "alice@example.com" }
  }
}
```

### 2. HMAC Validation
Webhook header `X-Zoho-Signature` is validated against `HMAC_SECRET`.

### 3. Approval Detection
Comment text is matched against `APPROVAL_REGEX`. If matched, proceed to escalation.

### 4. Approver Verification
`alice@example.com` is checked against `SENIOR_APPROVERS` list. If authorized, proceed.

### 5. Idempotency Check
Query `grants.jsonl` to see if an active grant already exists for this ticket/user/role.

### 6. Authentication
Call `Get-DelineaToken` to obtain bearer token via OAuth flow.

### 7. Privilege Escalation
Call `Invoke-DelineaPrivilegeEscalation` with:
- **User**: `dev@company.com`
- **Duration**: 7200 seconds (2 hours)

### 8. Audit Logging
Append grant record to `grants.jsonl`:
```json
{
  "workitemId": "12345",
  "user": "dev@company.com",
  "role": "prod-app-01",
  "grantedAt": "2025-12-03T14:30:00Z",
  "expiresAt": "2025-12-03T16:30:00Z",
  "revokedAt": null,
  "revokeReason": null
}
```

### 9. Zoho Comment Update
Post a comment to the ticket confirming the escalation:
```
✅ Privilege escalation granted for dev@company.com
Duration: 2 hours
Expires at: 2025-12-03T16:30:00Z
```

### 10. TTL-Based Auto-Revocation
RevokeWorker runs every 60 seconds (configurable). When grant expires:
1. Query `grants.jsonl` for expired grants
2. Call `Invoke-DelineaPrivilegeRevoke` for each
3. Append revocation record with `revokedAt` timestamp

## Error Handling

### Idempotent Scenarios

| Status Code | Meaning | Handled As |
|-------------|---------|-----------|
| 200 | Success | ✅ Success |
| 409 | Already escalated | ✅ Success (no-op) |
| 404 | Privilege not active (on revoke) | ✅ Success (no-op) |

### Failure Scenarios

| Scenario | Logging | Recovery |
|----------|---------|----------|
| Auth token retrieval fails | ❌ ERROR logged | Webhook returns 400 to Zoho |
| Privilege escalation fails | ❌ ERROR logged | Zoho comment: "Grant failed: <error>" |
| Zoho comment post fails | ⚠️ WARN logged | Grant still created (audit issue only) |
| Revocation fails (unexpected) | ❌ ERROR logged | RevokeWorker retries on next cycle |

## Testing

### Manual Test (Using Mock APIs)

**Prerequisites:**
```bash
# Terminal 1: Start Mock Delinea API
powershell -ExecutionPolicy Bypass -File ./mock-delinea.ps1

# Terminal 2: Start Mock Zoho API
powershell -ExecutionPolicy Bypass -File ./mock-zoho.ps1

# Terminal 3: Load environment and start webhook
$env:DELINEA_API_BASE = "http://localhost:19002"
$env:ZOHO_API_BASE = "http://localhost:19001"
. ./webhook.ps1
Start-Listener
```

**Send Test Request:**
```powershell
# Compute HMAC signature
$body = @{
  ticket = @{ id = "12345"; assignee = @{ email = "dev@example.com" } }
  comment = @{ text = "/approve"; author = @{ email = "alice@example.com" } }
} | ConvertTo-Json

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [System.Text.Encoding]::UTF8.GetBytes("local_test_secret")
$signature = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body)))

# Send request
$params = @{
  Uri = "http://127.0.0.1:9090/webhook"
  Method = "POST"
  Headers = @{
    'Content-Type' = 'application/json'
    'X-Zoho-Signature' = $signature
  }
  Body = $body
}
Invoke-RestMethod @params
```

**Verify Grant Created:**
```powershell
Get-Content grants.jsonl | ConvertFrom-Json | Format-Table
```

### Integration Test (Production Delinea)

Update `.env` with real Delinea credentials:
```env
DELINEA_API_BASE=https://your-tenant.delinea.com
DELINEA_CLIENT_ID=your_client_id@your_tenant
DELINEA_CLIENT_SECRET=your_client_secret
```

Then follow the manual test steps above. The webhook will authenticate against your real Delinea instance.

## Troubleshooting

### Issue: "Could not obtain Delinea authentication token"

**Causes:**
1. `DELINEA_API_BASE` not set or unreachable
2. `DELINEA_CLIENT_ID` or `DELINEA_CLIENT_SECRET` incorrect
3. Network connectivity issue

**Solution:**
```powershell
# Test connectivity
Invoke-RestMethod -Uri "$env:DELINEA_API_BASE/Security/StartChallenge" -Method Post -Body "{}"

# Verify credentials
Write-Host "DELINEA_API_BASE: $env:DELINEA_API_BASE"
Write-Host "DELINEA_CLIENT_ID: $env:DELINEA_CLIENT_ID"
Write-Host "DELINEA_CLIENT_SECRET: [hidden]"
```

### Issue: "Delinea privilege escalation already active"

**Meaning:** Privilege already escalated for this user. This is treated as a successful no-op (idempotent).

**Solution:** No action needed. The webhook correctly handles this case.

### Issue: "Approval regex not matching"

**Causes:**
1. Comment text doesn't match `APPROVAL_REGEX`
2. Approver not in `SENIOR_APPROVERS` list

**Solution:**
```powershell
# Test regex
$comment = "/approve me"
if ($comment -match "^\s*(\/?approve|approved|ack|ok|accepted|✅|\u2705)\b") {
  Write-Host "Regex matches!"
}

# Check approver
Write-Host "SENIOR_APPROVERS: $env:SENIOR_APPROVERS"
$approvers = $env:SENIOR_APPROVERS -split ',' | ForEach-Object { $_.Trim().ToLower() }
$isApprover = $approvers -contains "alice@example.com"
Write-Host "Is alice@example.com approved? $isApprover"
```

## API Reference

### Delinea Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/Security/StartChallenge` | POST | Initiate authentication challenge |
| `/Security/AdvanceAuthentication` | POST | Submit credentials to complete auth |
| `/uprest/HandleAppClick` | POST | Escalate or revoke privilege |

### Request/Response Examples

See **Authentication Flow** section above for detailed examples.

## Security Notes

1. **Credentials in .env**: Store securely (not in Git)
2. **Bearer Token**: Valid for session duration; consider token refresh logic for long-running processes
3. **HMAC Secret**: Use strong random string for production
4. **Log Redaction**: Sensitive fields (tokens, secrets, passwords) are automatically redacted in logs
5. **Audit Trail**: All grants/revocations recorded in `grants.jsonl` with timestamps

## References

- [Delinea Privilege Elevation API Documentation](https://developer.delinea.com/docs/privilege-elevation)
- [Delinea Cloud Suite API Reference](https://developer.delinea.com/reference)
- [WebHook Integration Guide](./WEBHOOK_INTEGRATION.md)
- [Setup Instructions](./SETUP_GUIDE.md)
