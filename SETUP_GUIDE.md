# Cookiejar Webhook Service - Setup & Execution Guide

## Quick Start (5 minutes)

### Prerequisites
- PowerShell 5.1 or later
- Windows OS (for file paths)
- Network connectivity (localhost)

### Step 1: Navigate to Project Directory

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
```

### Step 2: Create Environment Configuration

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-test.ps1
```

This creates `.env` file with:
- PORT=8090
- HMAC_SECRET=local_test_secret
- HMAC_REQUIRED=true
- Mock API endpoints

---

## Running the Services

Open **4 separate PowerShell terminals** and run each command in its own terminal:

### Terminal 1: Mock Delinea API (Port 19002)

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
powershell -ExecutionPolicy Bypass -File .\mock-delinea.ps1
```

**Expected Output:**
```
Starting Mock Delinea API on port 19002...
Mock Delinea listening on http://localhost:19002/
```

This mock accepts all requests and returns `{ "result": "ok" }`. Logs all incoming grant/revoke requests.

---

### Terminal 2: Mock Zoho API (Port 19001)

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
powershell -ExecutionPolicy Bypass -File .\mock-zoho.ps1
```

**Expected Output:**
```
Starting Mock Zoho API on port 19001...
Mock Zoho listening on http://localhost:19001/
```

This mock accepts all comment POST requests. Logs all interactions.

---

### Terminal 3: Main Webhook Service (Port 8090)

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1
```

**Expected Output:**
```
Loading environment variables from ...\cookiejar\.env
Loaded 10 environment variables
Sourcing webhook.ps1...
{"message":"Started RevokeWorker using Start-Job (background process)","timestamp":"...","level":"info",...}
{"message":"Starting HTTP listener","timestamp":"...","level":"info","data":{"port":8090}}
{"message":"Listening for incoming webhooks","timestamp":"...","level":"info","data":{"prefix":"http://127.0.0.1:8090/"}}
```

The webhook will now wait for incoming requests and log all activity in JSON format.

---

### Terminal 4: Send Test Requests

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
powershell -ExecutionPolicy Bypass -File .\run-full-test.ps1
```

**Expected Output:**
```
====== WEBHOOK SERVICE DRY RUN TEST ======

1. Services Status:
   ✓ Mock Delinea listening on port 19002
   ✓ Mock Zoho listening on port 19001
   ✓ Webhook listening on port 8090

2. Sending Test Request:
   Signature: AbCdEfGhIjKlMnOpQrStUv...
   POST to http://127.0.0.1:8090/
   ✓ HTTP Status: 200
   ✓ Response: ok

3. Checking Grants File:
   ✓ grants.jsonl exists
   Content: {"workitemId":12345,"user":"dev@example.com","role":"role_prod_app_server_01",...}

====== TEST COMPLETE ======
```

---

## What Each Service Does

### Mock Delinea API
- **Purpose:** Simulates Delinea Secret Server API
- **Endpoints:**
  - `POST /api/roleAssignments` - Grant access (logs request, returns 200)
  - `POST /api/roleAssignments/revoke` - Revoke access (logs request, returns 200)
- **Port:** 19002
- **Check:** Look for log entries with `[HH:mm:ss] DELINEA MOCK:`

### Mock Zoho API
- **Purpose:** Simulates Zoho Sprints API
- **Endpoints:**
  - `POST /sprints/v1/tickets/{id}/comments` - Post comments (logs request, returns 200)
- **Port:** 19001
- **Check:** Look for log entries with `[HH:mm:ss] ZOHO MOCK:`

### Webhook Service
- **Purpose:** Main integration service
- **Responsibilities:**
  1. Listens for Zoho webhook events
  2. Validates HMAC signatures
  3. Detects approval comments
  4. Grants access via Delinea
  5. Posts status comments back to Zoho
  6. Persists grants to `grants.jsonl`
  7. Auto-revokes expired grants (60-second intervals)
- **Port:** 8090
- **Check:** Look for JSON-formatted log entries

---

## Testing Scenarios

### Test 1: Valid Approval from Senior Approver
The `run-full-test.ps1` script automatically tests this. You should see:
1. ✓ Webhook receives request (port 8090 logs)
2. ✓ HMAC signature validates
3. ✓ Delinea grant call made (port 19002 logs)
4. ✓ Comment posted to Zoho (port 19001 logs)
5. ✓ Entry added to `grants.jsonl`

### Test 2: Invalid HMAC Signature
Manually send with wrong signature:
```powershell
$body = Get-Content approve.json -Raw
curl -X POST http://localhost:8090/ `
  -H "Content-Type: application/json" `
  -H "X-Zoho-Signature: wrong_signature" `
  -d $body
```

Expected: **401 Unauthorized** response

### Test 3: Non-Approver Comment
Edit `approve.json` and change `"alice@example.com"` to `"bob@example.com"` (not in SENIOR_APPROVERS), then send request.

Expected: Comment logged but no grant made (status 200 but "ignored")

---

## Configuration Options

### Environment Variables (.env file)

| Variable | Default | Purpose |
|----------|---------|---------|
| PORT | 8090 | Webhook listener port |
| HMAC_SECRET | - | Shared secret for HMAC verification |
| HMAC_REQUIRED | true | Enforce HMAC validation |
| ZOHO_API_BASE | http://localhost:19001 | Zoho API endpoint |
| DELINEA_API_BASE | http://localhost:19002 | Delinea API endpoint |
| SENIOR_APPROVERS | alice@example.com | Comma-separated list of approvers |
| GRANTS_STORE | grants.jsonl | File to store grant records |
| REVOKE_WORKER_INTERVAL_SECONDS | 60 | TTL check interval |

---

## Monitoring & Debugging

### View Webhook Logs (Real-time)
The webhook outputs JSON-formatted logs. Look for:
```json
{"level":"info","message":"Received webhook event",...}
{"level":"info","message":"Comment details",...}
{"level":"info","message":"Access granted and persisted",...}
```

### Check Grants File
```powershell
Get-Content grants.jsonl | ConvertFrom-Json | Format-Table
```

### Monitor Delinea Mock
Terminal 1 will show all incoming grant/revoke requests with headers and body.

### Monitor Zoho Mock
Terminal 2 will show all incoming comment POST requests.

---

## Stopping Services

Simply press **Ctrl+C** in each terminal to stop the service gracefully.

The services will exit cleanly and release all ports.

---

## Troubleshooting

### Issue: "Access denied" on port 8090
- Ports < 1024 require admin privileges
- Solution: Use ports > 1024 (already configured as 8090, 19001, 19002)

### Issue: Webhook starts but doesn't receive requests
- Check all three background services are running
- Verify URLs point to `127.0.0.1` not `localhost`
- Check firewall isn't blocking local connections

### Issue: "Start-RevokeWorker not found"
- webhook.ps1 not sourced correctly
- Solution: Run setup-test.ps1 first, then start-webhook.ps1

### Issue: HMAC signature validation fails
- Ensure HMAC_SECRET matches both webhook and client
- Default: `local_test_secret`
- Verify the signature computation: `New-ZohoSignature -body $payload -secret 'local_test_secret'`

### Issue: Grants file not created
- Normal if no valid approvals sent
- Check webhook logs for "Access granted and persisted"
- File is created on first successful grant

---

## Next Steps

1. **Run the dry run** to verify all services work
2. **Send test requests** using `run-full-test.ps1`
3. **Check logs** in Terminal 3 (webhook)
4. **Verify grants.jsonl** was created with grant records
5. **Test Zoho integration** with real Zoho instance (update ZOHO_API_BASE)
6. **Test Delinea integration** with real Delinea instance (update DELINEA_API_BASE)

---

## File Reference

| File | Purpose |
|------|---------|
| `webhook.ps1` | Main webhook service logic (577 lines) |
| `start-webhook.ps1` | Startup script that loads .env and starts webhook |
| `mock-delinea.ps1` | Mock Delinea API for testing |
| `mock-zoho.ps1` | Mock Zoho API for testing |
| `setup-test.ps1` | Creates .env with test configuration |
| `approve.json` | Sample approval payload for testing |
| `run-full-test.ps1` | Comprehensive test runner with validation |
| `grants.jsonl` | Persistent grant record storage (created automatically) |
| `.env` | Environment configuration (created by setup-test.ps1) |

---

## Production Deployment

To deploy to production:

1. Update `.env` with real API endpoints
2. Update SENIOR_APPROVERS with actual approver emails
3. Update ZOHO_API_BASE and DELINEA_API_BASE
4. Ensure HMAC_SECRET is strong (generate new one)
5. Set HMAC_REQUIRED=true (verify before setting)
6. Change PORT if needed
7. Run: `powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1`

All logs will output to console in JSON format suitable for log aggregation systems (ELK, Splunk, etc.).
