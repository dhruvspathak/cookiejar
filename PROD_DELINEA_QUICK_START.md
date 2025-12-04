# Production Delinea Testing - Quick Start

## Configuration

Your system is now configured for:
- ✅ **Real Delinea:** `https://cookiejar.delinea.app`
- ✅ **Real Credentials:** `dhruvap@cookiejar` / `GoldGreen@21`
- ✅ **Mock Zoho:** `http://localhost:19001`

All configured in `.env` - no code changes needed!

## Quick Test (3 Steps)

### Step 1: Verify Delinea Connection

```powershell
powershell -ExecutionPolicy Bypass -File .\prod-delinea-test.ps1
```

✓ Should show "✓ Authentication SUCCESSFUL"

### Step 2: Start Webhook with Production Delinea

```powershell
powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1
```

✓ Should show "Listening for incoming webhooks" on port 9090

### Step 3: Run Full Integration Test

```powershell
powershell -ExecutionPolicy Bypass -File .\run-full-test.ps1
```

✓ Should show "✓ TEST PASSED: Webhook received request and escalated to production Delinea"

## What Gets Tested

| Component | Type | Status |
|-----------|------|--------|
| Delinea OAuth2 Auth | Real | ✓ Production |
| Privilege Escalation | Real | ✓ Production |
| Privilege Revocation | Real | ✓ Production |
| Zoho Notifications | Mock | ⊙ Local |
| Webhook Listener | Local | ⊙ Local |

## Expected Workflow

1. **prod-delinea-test.ps1**
   - Connects to real Delinea
   - Authenticates with real credentials
   - Shows: "✓ Production Delinea is reachable"

2. **start-webhook.ps1**
   - Loads production Delinea config from `.env`
   - Starts webhook listener
   - Shows: "Listening for incoming webhooks"

3. **run-full-test.ps1**
   - Sends approval event to webhook
   - Webhook authenticates with **production Delinea**
   - Webhook escalates privilege in **production Delinea**
   - Shows: "✓ TEST PASSED"
   - Creates grant record in `grants.jsonl`

## Files Changed

- ✅ `.env` - Updated with production Delinea credentials
- ✅ `run-full-test.ps1` - Updated to use production Delinea
- ✅ `prod-delinea-test.ps1` - NEW - Tests production connectivity
- ✅ `PROD_DELINEA_TESTING.md` - NEW - Full testing guide

## Verification Checklist

Before running tests:
- [ ] `.env` has real Delinea URL: `https://cookiejar.delinea.app`
- [ ] `.env` has real credentials
- [ ] Network can reach Delinea (not blocked by firewall/proxy)

After tests:
- [ ] `prod-delinea-test.ps1` shows successful authentication
- [ ] Webhook starts without errors
- [ ] `run-full-test.ps1` shows HTTP 200 response
- [ ] `grants.jsonl` has new grant record
- [ ] Check Delinea UI - privilege should be active for target user

## Troubleshooting

**❌ "Delinea API unreachable"**
→ Run `prod-delinea-test.ps1` first to diagnose

**❌ "Authentication failed"**
→ Check credentials in `.env` match your Delinea account

**❌ "HTTP timeout"**
→ Delinea may be slow - check network connectivity

**✓ "Authentication SUCCESSFUL"**
→ Great! Everything is configured correctly

## Key Logs to Monitor

In webhook terminal, look for:
```
"Starting Delinea authentication challenge at: https://cookiejar.delinea.app/Security/StartChallenge"
"Delinea authentication successful"
"Invoking Delinea Privilege Escalation"
"Delinea privilege escalation success"
```

## Test Payload

The test sends this approval event:
```json
{
  "event": "comment.added",
  "ticket": {
    "id": 12345,
    "assignee": {"email": "dev@example.com"}
  },
  "comment": {
    "text": "approved",
    "author": {"email": "alice@example.com"}
  }
}
```

Expected result:
- ✓ Delinea authenticates with OAuth2
- ✓ Privilege escalated for `dev@example.com`
- ✓ Duration: 2 hours (configurable)
- ✓ Grant record saved to `grants.jsonl`

## URLs Being Called

When you run the tests, the webhook will call:

1. **Authentication:**
   - `POST https://cookiejar.delinea.app/Security/StartChallenge`
   - `POST https://cookiejar.delinea.app/Security/AdvanceAuthentication`

2. **Escalation:**
   - `POST https://cookiejar.delinea.app/uprest/HandleAppClick`

3. **Mock (for testing notification):**
   - `POST http://localhost:19001/sprints/v1/tickets/12345/comments`

---

**Ready to test with production Delinea! 🚀**

Run: `powershell -File .\prod-delinea-test.ps1`
