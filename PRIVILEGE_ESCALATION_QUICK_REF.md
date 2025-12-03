# Privilege Escalation Quick Reference

## What Changed?

The webhook now implements **Delinea's official Privilege Escalation API** instead of a generic role assignment API.

### Old Approach (Removed)
```powershell
POST /api/roleAssignments
{ "user": "dev@example.com", "role": "prod-app-01" }
```

### New Approach (Delinea OAuth + Privilege Escalation)
```
1. Authenticate with OAuth
   POST /Security/StartChallenge     → Get challenge
   POST /Security/AdvanceAuthentication → Get bearer token

2. Escalate privilege with bearer token
   POST /uprest/HandleAppClick       → Grant privilege (time-limited)
   POST /uprest/HandleAppClick?action=revoke → Revoke privilege
```

## Key Functions

### `Get-DelineaToken` (Lines 109-165)
Handles complete OAuth authentication. Returns bearer token or $null on failure.

**Usage:**
```powershell
$token = Get-DelineaToken
if ($token) {
  Write-Host "Authentication successful: $token"
}
```

### `Invoke-DelineaPrivilegeEscalation` (Lines 249-297)
Grants temporary privilege to a user for specified duration.

**Usage:**
```powershell
$result = Invoke-DelineaPrivilegeEscalation -targetUser "dev@example.com" -durationSeconds 7200
if ($result.success) {
  Write-Host "Privilege granted for 2 hours"
}
```

### `Invoke-DelineaPrivilegeRevoke` (Lines 299-334)
Revokes privilege escalation.

**Usage:**
```powershell
$result = Invoke-DelineaPrivilegeRevoke -targetUser "dev@example.com"
if ($result.success) {
  Write-Host "Privilege revoked"
}
```

## Configuration Checklist

- [ ] `.env` file contains correct `DELINEA_API_BASE` (without `/api` suffix)
- [ ] `.env` contains valid `DELINEA_CLIENT_ID` (usually an email)
- [ ] `.env` contains valid `DELINEA_CLIENT_SECRET` (provided by Delinea)
- [ ] Delinea instance is reachable from webhook server
- [ ] Firewall allows outbound HTTPS to Delinea API
- [ ] Service account has permission to escalate privileges

## Workflow

```
Zoho Approval Event
    ↓
[HMAC Validation] ✓
    ↓
[Approval Text Match] ✓ (/approve, ack, ok, etc.)
    ↓
[Senior Approver Check] ✓ (in SENIOR_APPROVERS list)
    ↓
[Idempotency Check] ✓ (no duplicate active grant)
    ↓
[OAuth Auth] Get-DelineaToken
    ↓
[Escalate] Invoke-DelineaPrivilegeEscalation
    ↓
[Audit] Append to grants.jsonl
    ↓
[Notify] Post comment to Zoho ticket
    ↓
[Auto-Revoke] RevokeWorker on TTL expiry
```

## Error Codes Handled

| Code | Scenario | Result |
|------|----------|--------|
| 200 | Success | ✅ Grant/Revoke created |
| 409 | Already escalated | ✅ No-op (idempotent) |
| 404 | Not escalated (on revoke) | ✅ No-op (idempotent) |
| 4xx | Auth/validation error | ❌ Returns error to Zoho |
| 5xx | Server error | ❌ Returns error to Zoho |

## Authentication Flow (Simplified)

```
┌─────────────────────────────────────────────────┐
│ Start Challenge                                 │
│ User: DELINEA_CLIENT_ID                         │
│ Secret: DELINEA_CLIENT_SECRET                   │
└─────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────┐
│ Advance Authentication                          │
│ Answer: DELINEA_CLIENT_SECRET                   │
└─────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────┐
│ Bearer Token Received                           │
│ Authorization: Bearer <token>                   │
└─────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────┐
│ Escalate/Revoke Privilege                       │
│ Use bearer token for subsequent calls           │
└─────────────────────────────────────────────────┘
```

## Testing

### Test Authentication
```powershell
# Load webhook
. ./webhook.ps1

# Try to get token
$token = Get-DelineaToken
if ($token) {
  Write-Host "✅ Authentication successful"
  Write-Host "Token: $token"
} else {
  Write-Host "❌ Authentication failed - check credentials"
}
```

### Test Full Workflow
```powershell
# Load webhook and mock APIs
. ./webhook.ps1

# Start services
Start-Listener  # Port 9090
Start-RevokeWorker

# Send test request with HMAC signature
# (See PRIVILEGE_ESCALATION_GUIDE.md for full example)
```

### Debug Logs
```powershell
# All authentication/escalation logs go to stdout
# Check for patterns:
# - "Starting Delinea authentication challenge"
# - "Delinea authentication successful"
# - "Delinea privilege escalation success"
# - "Delinea privilege revocation success"
```

## Common Issues

**Q: "Could not obtain Delinea authentication token"**  
A: Check that `DELINEA_API_BASE`, `DELINEA_CLIENT_ID`, and `DELINEA_CLIENT_SECRET` are correctly set in `.env`.

**Q: "Delinea privilege escalation already active"**  
A: This is normal - it means the privilege was already escalated (idempotent). No action needed.

**Q: "Approval regex not matching"**  
A: Verify the comment contains one of: `/approve`, `approved`, `ack`, `ok`, `accepted`, `✅`

**Q: "No target user found for grant"**  
A: Check that the ticket has an assignee or a `targetUser` field populated.

## .env Example

```env
# Delinea Instance
DELINEA_API_BASE=https://cookiejar.delinea.app
DELINEA_CLIENT_ID=dhruvap@cookiejar
DELINEA_CLIENT_SECRET=GoldGreen@21

# Or use pre-generated token
DELINEA_OAUTH_TOKEN=DE01F612EC5B81DD05E...

# Webhook settings
PORT=9090
HMAC_SECRET=your_secure_secret_here
HMAC_REQUIRED=true

# Approvers
SENIOR_APPROVERS=alice@example.com,bob@example.com

# Zoho (mock or real)
ZOHO_API_BASE=http://localhost:19001
```

## Next Steps

1. ✅ Review `PRIVILEGE_ESCALATION_GUIDE.md` for detailed documentation
2. ✅ Update `.env` with your Delinea credentials
3. ✅ Test authentication with `Get-DelineaToken`
4. ✅ Start webhook with `Start-Listener`
5. ✅ Send test approval event
6. ✅ Verify grant in `grants.jsonl`
7. ✅ Monitor TTL auto-revocation

## Resources

- [Delinea Privilege Elevation API](https://developer.delinea.com/docs/privilege-elevation)
- [Webhook Service Code](./webhook.ps1)
- [Full Documentation](./PRIVILEGE_ESCALATION_GUIDE.md)
- [Setup Guide](./SETUP_GUIDE.md)
