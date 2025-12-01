# QUICK START CHECKLIST

## 1. Open 4 PowerShell Windows

Window 1, 2, 3, 4 (CMD or PowerShell Core)

---

## 2. In Each Window, CD to Project:

```powershell
cd "D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar"
```

---

## 3. RUN IN THIS ORDER:

### Window 1: Setup Environment (Run Once)
```powershell
powershell -ExecutionPolicy Bypass -File .\setup-test.ps1
```
Wait for: `Loaded 10 environment variables`

---

### Window 1 → Terminal 1 (Keep Running)
```powershell
powershell -ExecutionPolicy Bypass -File .\mock-delinea.ps1
```
Wait for: `Mock Delinea listening on http://localhost:19002/`

---

### Window 2 → Terminal 2 (Keep Running)
```powershell
powershell -ExecutionPolicy Bypass -File .\mock-zoho.ps1
```
Wait for: `Mock Zoho listening on http://localhost:19001/`

---

### Window 3 → Terminal 3 (Keep Running)
```powershell
powershell -ExecutionPolicy Bypass -File .\start-webhook.ps1
```
Wait for: `Listening for incoming webhooks`

---

### Window 4 → Terminal 4 (Run Tests)
```powershell
powershell -ExecutionPolicy Bypass -File .\run-full-test.ps1
```
Expected: All tests pass with ✓ marks

---

## 4. VERIFY SUCCESS

Look for in Terminal 4 output:
- ✓ Mock Delinea listening on port 19002
- ✓ Mock Zoho listening on port 19001  
- ✓ Webhook listening on port 8090
- ✓ HTTP Status: 200
- ✓ Response: ok

---

## 5. CHECK OUTPUTS

- **Terminal 1 (Delinea):** Should show `[HH:mm:ss] DELINEA MOCK: POST /api/roleAssignments`
- **Terminal 2 (Zoho):** Should show `[HH:mm:ss] ZOHO MOCK: POST /sprints/v1/tickets/...`
- **Terminal 3 (Webhook):** Should show grant/revoke JSON logs
- **Terminal 4 (Test):** Shows test results

---

## 6. CLEANUP

Press **Ctrl+C** in each terminal to stop all services gracefully

---

## TROUBLESHOOTING

| Issue | Solution |
|-------|----------|
| "Access denied" on startup | Run PowerShell as Administrator |
| Port already in use | Another instance running; use Ctrl+C to stop |
| Tests fail with connection error | Ensure all 3 services started first |
| .env not found | Run `setup-test.ps1` first |
| HMAC validation fails | Check HMAC_SECRET in .env matches (local_test_secret) |

---

## KEY PATHS

```
Project: D:\OneDrive - Inflow Technologies Pvt Ltd\Desktop\work-folder\thumos\cookiejar-local\cookiejar
Files:
  - webhook.ps1 (main service)
  - start-webhook.ps1 (launcher)
  - mock-delinea.ps1 (mock API)
  - mock-zoho.ps1 (mock API)
  - approve.json (test payload)
  - .env (created by setup-test.ps1)
  - grants.jsonl (created after first grant)
```

---

## INTEGRATION ENDPOINTS

- Webhook listens: `http://127.0.0.1:8090/`
- Delinea API mock: `http://localhost:19002/`
- Zoho API mock: `http://localhost:19001/`

For production, update .env with real endpoints.

---

## CONFIGURATION

Edit .env file to customize:
- PORT=8090
- HMAC_SECRET=local_test_secret
- ZOHO_API_BASE=http://localhost:19001
- DELINEA_API_BASE=http://localhost:19002
- SENIOR_APPROVERS=alice@example.com
- REVOKE_WORKER_INTERVAL_SECONDS=60

---

## MONITORING

View live logs from webhook:
```powershell
Get-Content grants.jsonl | ConvertFrom-Json | Format-Table workitemId, user, role, grantedAt, expiresAt
```

All webhook logs output to console in JSON format.
