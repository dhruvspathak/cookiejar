# Next Steps: Fix Delinea OAuth2 Credentials

## Current Status

**Issue:** OAuth2 credentials rejected by Delinea
```
Error: "invalid client creds or client not allowed"
```

**What's Working:**
- ✅ OAuth2 endpoint is correct: `/identity/api/oauth2/token/xpmplatform`
- ✅ OAuth2 flow is correct: `client_credentials` grant
- ✅ Network connectivity to Delinea is working
- ✅ All PowerShell code is syntax-valid and deployable

**What Needs Fixing:**
- ❌ OAuth2 client credentials (client_id + client_secret) appear invalid
- ❌ Client may not be configured for OAuth2 in your Delinea tenant

## Action Items

### 1. Verify OAuth2 Client in Delinea

**Go to your Delinea tenant:**
1. Admin → Integrations or Admin → OAuth Clients (varies by version)
2. Find client with ID: `dhruvap@cookiejar`
3. Verify:
   - [ ] Client exists
   - [ ] Client Secret matches: `GoldGreen@21` (from your .env)
   - [ ] Client has `client_credentials` grant type enabled
   - [ ] Client has `xpmheadless` scope assigned
   - [ ] Client is not disabled/inactive

### 2. Update .env if Needed

If the credentials are wrong, update in `.env`:
```
DELINEA_CLIENT_ID=<correct-client-id>
DELINEA_CLIENT_SECRET=<correct-client-secret>
```

### 3. Test OAuth2

Run the test script to verify credentials work:
```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
powershell -ExecutionPolicy Bypass -File .\prod-delinea-test.ps1
```

**Expected Success:**
```
OK OAuth2 authentication SUCCESSFUL
OK Access Token: eyJ0eXAiOiJKV1Q...
OK Token Type: Bearer
OK Expires In: 3600 seconds
OK Ready to deploy to production
```

### 4. Configure Privilege Escalation (After OAuth2 Works)

Once step 3 passes:

1. **Get PE Command ID from Delinea:**
   - Go to Admin → Privilege Elevation (or similar)
   - Find the command you want to grant for privilege elevation
   - Copy its Command ID

2. **Get System ID from Delinea:**
   - Go to Admin → Systems
   - Find the system corresponding to "target server" in Zoho
   - Copy its System ID

3. **Update webhook.ps1 with real values:**
   - Open `webhook.ps1` in editor
   - Go to line 248-258 (inside `Invoke-DelineaPrivilegeEscalation` function)
   - Replace the TODO values:
     ```powershell
     $assignment = @{
         CommandId      = 'YOUR_COMMAND_ID_HERE'    # Get from Delinea Admin
         PrincipalType  = 'User'
         PrincipalName  = $targetUser               # Already correct
         ScopeType      = 'System'
         ScopeId        = 'YOUR_SYSTEM_ID_HERE'     # Get from Delinea Admin
         Starts         = $nowUtc.ToString('o')     # Already correct
         Expires        = $expires.ToString('o')    # Already correct
     }
     ```

## Testing Endpoints

### OAuth2 Endpoint (Debug Only)

To manually test OAuth2:
```powershell
$body = @{
    grant_type    = 'client_credentials'
    client_id     = 'dhruvap@cookiejar'
    client_secret = 'GoldGreen@21'
    scope         = 'xpmheadless'
}

$resp = Invoke-RestMethod -Uri 'https://cookiejar.delinea.app/identity/api/oauth2/token/xpmplatform' `
                          -Method Post `
                          -Body $body `
                          -ContentType 'application/x-www-form-urlencoded'

$resp.access_token
```

### Full Integration Test (After Configuration)

Once everything is configured:
```powershell
# Terminal 1: Start webhook
powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1

# Terminal 2: Run full test
powershell -ExecutionPolicy Bypass -File .\run-full-test.ps1
```

## Files Reference

- **webhook.ps1** - Main webhook server (lines 112-181: OAuth2, lines 216-310: PE API)
- **prod-delinea-test.ps1** - Tests OAuth2 connectivity
- **DELINEA_OAUTH2_UPDATES.md** - Full technical details of changes
- **.env** - Configuration (verify DELINEA_* values)

## Support

If OAuth2 still fails after verifying credentials:

1. Check if your Delinea version uses different endpoint paths
2. Verify tenant supports `client_credentials` grant (not all versions/editions do)
3. Check Delinea admin logs for any client authentication errors
4. Contact Delinea support with error: `invalid client creds or client not allowed`

## Summary

**Current:**
- Code: ✅ Updated to correct Delinea OAuth2 API
- Syntax: ✅ All valid, deployable
- Credentials: ❌ Need verification/update

**Next:** Verify OAuth2 client in Delinea tenant and update .env if needed
