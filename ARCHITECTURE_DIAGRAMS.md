# Delinea Privilege Escalation Architecture Diagram

## Complete Integration Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         ZOHO SPRINTS WORKFLOW                                │
│  User creates ticket → Approver adds comment → Webhook receives event      │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                     COOKIEJAR WEBHOOK SERVICE (PORT 9090)                    │
│                                                                              │
│  ┌─ VALIDATION ──────────────────────────────────────────────────────────┐  │
│  │ 1. HMAC Signature Verification (X-Zoho-Signature)                   │  │
│  │    ├─ Secret: $env:HMAC_SECRET                                      │  │
│  │    ├─ Algorithm: HMACSHA256                                         │  │
│  │    └─ Status: ✅ VALID → Continue | ❌ INVALID → Reject (401)     │  │
│  │                                                                      │  │
│  │ 2. Approval Detection (Regex Match)                                 │  │
│  │    ├─ Pattern: ^\s*(\/?approve|approved|ack|ok|accepted|✅)        │  │
│  │    └─ Status: ✅ MATCH → Continue | ❌ NO MATCH → Reject (400)    │  │
│  │                                                                      │  │
│  │ 3. Senior Approver Authorization                                    │  │
│  │    ├─ Approver Email: $comment.author.email                        │  │
│  │    ├─ Allowed List: $env:SENIOR_APPROVERS (comma-separated)        │  │
│  │    └─ Status: ✅ AUTHORIZED → Continue | ❌ UNAUTHORIZED → 403    │  │
│  │                                                                      │  │
│  │ 4. Idempotency Check                                                │  │
│  │    ├─ Query: grants.jsonl for active grant                         │  │
│  │    ├─ Filter: Same workitemId, user, role, revokedAt=null         │  │
│  │    └─ Status: ✅ NONE → Continue | ⚠️ ACTIVE → Return existing   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│                                    ↓ (All validations passed)              │
│                                                                              │
│  ┌─ OAUTH2 AUTHENTICATION (Get-DelineaToken) ─────────────────────────────┐ │
│  │                                                                        │ │
│  │  ┌─ Step 1: Start Challenge ──────────────────────────────────────┐  │ │
│  │  │ POST /Security/StartChallenge                                 │  │ │
│  │  │ {                                                             │  │ │
│  │  │   "TenantId": "",                                             │  │ │
│  │  │   "User": "$env:DELINEA_CLIENT_ID",                          │  │ │
│  │  │   "Version": "1.0",                                           │  │ │
│  │  │   "AssociatedEntityType": "API",                             │  │ │
│  │  │   "AssociatedEntityName": "CookieJar"                        │  │ │
│  │  │ }                                                             │  │ │
│  │  │                                                               │  │ │
│  │  │ Response:                                                    │  │ │
│  │  │ {                                                             │  │ │
│  │  │   "success": true,                                            │  │ │
│  │  │   "Result": {                                                 │  │ │
│  │  │     "SessionId": "T0zrHgE6kkKdj...",                        │  │ │
│  │  │     "TenantId": "AAA0004",                                    │  │ │
│  │  │     "Challenges": [{                                          │  │ │
│  │  │       "Mechanisms": [{                                        │  │ │
│  │  │         "MechanismId": "Wdf7j9cqyu6Ymo...",                │  │ │
│  │  │         "Name": "PASSWORD",                                   │  │ │
│  │  │         ...                                                   │  │ │
│  │  │       }]                                                      │  │ │
│  │  │     }]                                                        │  │ │
│  │  │   }                                                            │  │ │
│  │  │ }                                                              │  │ │
│  │  └──────────────────────────────────────────────────────────────┘  │ │
│  │                                    │                                 │ │
│  │                                    ↓                                 │ │
│  │  ┌─ Step 2: Advance Authentication ───────────────────────────────┐ │ │
│  │  │ POST /Security/AdvanceAuthentication                         │ │ │
│  │  │ {                                                            │ │ │
│  │  │   "TenantId": "AAA0004",                                     │ │ │
│  │  │   "SessionId": "T0zrHgE6kkKdjs...",                        │ │ │
│  │  │   "MechanismId": "Wdf7j9cqyu6Ymoq...",                    │ │ │
│  │  │   "Answer": "$env:DELINEA_CLIENT_SECRET",                  │ │ │
│  │  │   "Action": "Answer"                                        │ │ │
│  │  │ }                                                            │ │ │
│  │  │                                                              │ │ │
│  │  │ Response:                                                   │ │ │
│  │  │ {                                                            │ │ │
│  │  │   "success": true,                                           │ │ │
│  │  │   "Result": {                                                │ │ │
│  │  │     "Auth": "DE01F612EC5B81DD05E...",   ← BEARER TOKEN      │ │ │
│  │  │     "User": "dhruvap@cookiejar",                           │ │ │
│  │  │     "AuthLevel": "High",                                    │ │ │
│  │  │     "Summary": "LoginSuccess",                              │ │ │
│  │  │     ...                                                      │ │ │
│  │  │   }                                                           │ │ │
│  │  │ }                                                             │ │ │
│  │  └──────────────────────────────────────────────────────────────┘ │ │
│  │                                    │                                │ │
│  │                                    ↓ (Token extracted)              │ │
│  │                         Bearer Token Ready                          │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                      │
│                                    ↓                                      │
│  ┌─ PRIVILEGE ESCALATION (Invoke-DelineaPrivilegeEscalation) ───────────┐ │
│  │                                                                      │ │
│  │  POST /uprest/HandleAppClick                                       │ │
│  │  Authorization: Bearer DE01F612EC5B81DD05E...                      │ │
│  │  {                                                                   │ │
│  │    "user": "dev@example.com",    ← From ticket.assignee           │ │
│  │    "durationSeconds": 7200,      ← From ticket.customFields       │ │
│  │    "requestType": "privilege_escalation"                           │ │
│  │  }                                                                   │ │
│  │                                                                      │ │
│  │  Response (Success 200):                                           │ │
│  │  {                                                                   │ │
│  │    "result": "ok",                                                  │ │
│  │    ...                                                              │ │
│  │  }                                                                   │ │
│  │                                                                      │ │
│  │  Response (Already Escalated 409):                                 │ │
│  │  {                                                                   │ │
│  │    "error": "Privilege already escalated",                         │ │
│  │    ...                                                              │ │
│  │  }  ← Treated as SUCCESS (idempotent)                             │ │
│  │                                                                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                      │
│                                    ↓                                      │
│  ┌─ AUDIT LOGGING ───────────────────────────────────────────────────┐  │
│  │ Append to grants.jsonl:                                          │  │
│  │ {                                                                │  │
│  │   "workitemId": "12345",                                        │  │
│  │   "user": "dev@example.com",                                    │  │
│  │   "role": "prod-app-01",                                        │  │
│  │   "grantedAt": "2025-12-03T14:30:00Z",                          │  │
│  │   "expiresAt": "2025-12-03T16:30:00Z",    ← 2h from now        │  │
│  │   "revokedAt": null,                                            │  │
│  │   "revokeReason": null                                          │  │
│  │ }                                                                │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│                                    ↓                                      │
│  ┌─ ZOHO NOTIFICATION (Post-ZohoComment) ─────────────────────────────┐ │
│  │ POST $env:ZOHO_API_BASE/sprints/v1/tickets/12345/comments       │ │
│  │ {                                                                 │ │
│  │   "text": "✅ Privilege escalation granted for dev@example.com │ │
│  │           Duration: 2 hours                                      │ │
│  │           Expires at: 2025-12-03T16:30:00Z"                      │ │
│  │ }                                                                 │ │
│  └────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│                                    ↓                                      │
│                     Response to Webhook Caller: 200 OK                   │
│                     { "result": "ok" }                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ↓
                    ┌─ RevokeWorker (Background Job) ────┐
                    │ Interval: every 60 seconds         │
                    │ Query: grants.jsonl                │
                    │ Check: expiresAt <= Now()          │
                    │ Action: Call Invoke-DelineaPrivil- │
                    │         egeRevoke for each expired │
                    │ Append revocation record           │
                    │ TTL: 2025-12-03T16:30:00Z → REVOKE│
                    └────────────────────────────────────┘
                                    │
                                    ↓
        ┌─ Privilege Revocation (Invoke-DelineaPrivilegeRevoke) ────┐
        │                                                           │
        │ POST /uprest/HandleAppClick?action=revoke               │
        │ Authorization: Bearer DE01F612EC5B81DD05E...            │
        │ {                                                         │
        │   "user": "dev@example.com",                            │
        │   "action": "revoke"                                     │
        │ }                                                         │
        │                                                           │
        │ Response (Success or Already Revoked):                  │
        │ { "result": "ok" } or 404 (treated as success)         │
        │                                                           │
        │ Append to grants.jsonl:                                 │
        │ {                                                         │
        │   "workitemId": "12345",                                │
        │   "user": "dev@example.com",                            │
        │   "revokedAt": "2025-12-03T16:30:00Z",                 │
        │   "revokeReason": "TTL Expired"                         │
        │ }                                                         │
        │                                                           │
        └───────────────────────────────────────────────────────┘
```

---

## Component Interaction Diagram

```
                        ┌─────────────────┐
                        │  Zoho Sprints   │
                        │  (Ticket Event) │
                        └────────┬────────┘
                                 │
                                 ↓ (JSON + HMAC Signature)
┌───────────────────────────────────────────────────────────┐
│                   COOKIEJAR WEBHOOK                       │
│                   Port 9090 (HTTP Listener)              │
│                                                           │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Request Handler                                   │ │
│  │  ├─ HMAC Validation                               │ │
│  │  ├─ Approval Detection                            │ │
│  │  ├─ Approver Authorization                        │ │
│  │  └─ Orchestration                                 │ │
│  └────────────┬────────────────────────────────────────┘ │
│               │                                          │
│      ┌────────┴────────┬──────────────┐                  │
│      ↓                 ↓              ↓                  │
│  ┌─────────────┐  ┌──────────┐  ┌─────────────┐         │
│  │ Get-Delinea │  │ Invoke-  │  │  Post-Zoho  │         │
│  │ Token       │  │ Delinea  │  │  Comment    │         │
│  │             │  │ Privilege│  │             │         │
│  │ (OAuth2)    │  │ Escalate │  │ (Comment)   │         │
│  └────────┬────┘  └────┬─────┘  └────┬────────┘         │
│           │             │             │                  │
└───────────┼─────────────┼─────────────┼──────────────────┘
            │             │             │
            ↓             ↓             ↓
     ┌─────────────────────────┐   ┌──────────────┐
     │  DELINEA API            │   │  ZOHO API    │
     │  (Privilege Escalation) │   │  (Comments)  │
     │                         │   │              │
     │ /Security/Start         │   │ POST /       │
     │  Challenge              │   │ sprints/v1/  │
     │ /Security/Advance       │   │ tickets/{id}/│
     │  Authentication         │   │ comments     │
     │ /uprest/HandleAppClick  │   │              │
     │ (grant + revoke)        │   └──────────────┘
     │                         │
     └─────────────────────────┘
            │            ↑
            │ Escalate   │ Authenticate
            │            │
            └────────────┘

     Plus: RevokeWorker (Background Job)
           └─ Checks grants.jsonl every 60 seconds
              └─ Revokes expired privileges
```

---

## Data Flow

```
REQUEST
  │
  ├─ Zoho Webhook Event
  │  {
  │    "ticket": {
  │      "id": "12345",
  │      "customFields": [
  │        {"name": "Server", "value": "prod-app-01"},
  │        {"name": "Duration", "value": "2h"}
  │      ],
  │      "assignee": {"email": "dev@example.com"}
  │    },
  │    "comment": {
  │      "text": "/approve",
  │      "author": {"email": "alice@example.com"}
  │    }
  │  }
  │  X-Zoho-Signature: <HMAC>
  │
  └─ Processing
     │
     ├─ Validation
     │  ├─ HMAC: ✅ Valid
     │  ├─ Approval: ✅ Matched "/approve"
     │  ├─ Approver: ✅ alice@example.com in SENIOR_APPROVERS
     │  └─ Idempotency: ✅ No duplicate grant
     │
     ├─ Authentication (Get-DelineaToken)
     │  ├─ POST /Security/StartChallenge
     │  │  → SessionId, TenantId, Challenges
     │  │
     │  └─ POST /Security/AdvanceAuthentication
     │     → Bearer: DE01F612EC5B81DD05E...
     │
     ├─ Escalation (Invoke-DelineaPrivilegeEscalation)
     │  └─ POST /uprest/HandleAppClick
     │     Authorization: Bearer DE01F612EC5B81DD05E...
     │     {user: dev@example.com, durationSeconds: 7200}
     │     → Result: {"result": "ok"}
     │
     ├─ Audit
     │  └─ grants.jsonl (Append)
     │     {
     │       workitemId: 12345,
     │       user: dev@example.com,
     │       role: prod-app-01,
     │       grantedAt: 2025-12-03T14:30:00Z,
     │       expiresAt: 2025-12-03T16:30:00Z,
     │       revokedAt: null,
     │       revokeReason: null
     │     }
     │
     └─ Notification (Post-ZohoComment)
        └─ POST /sprints/v1/tickets/12345/comments
           {"text": "✅ Privilege escalation granted..."}

RESPONSE
  │
  └─ HTTP 200 OK
     {"result": "ok"}

AUTO-REVOCATION (After 2 hours)
  │
  ├─ RevokeWorker detects expiry
  │  └─ Current time >= expiresAt (16:30:00Z)
  │
  ├─ Revocation (Invoke-DelineaPrivilegeRevoke)
  │  └─ POST /uprest/HandleAppClick?action=revoke
  │     Authorization: Bearer <token>
  │     {user: dev@example.com, action: revoke}
  │     → Result: {"result": "ok"}
  │
  └─ Audit
     └─ grants.jsonl (Append)
        {
          workitemId: 12345,
          user: dev@example.com,
          role: prod-app-01,
          revokedAt: 2025-12-03T16:30:00Z,
          revokeReason: "TTL Expired"
        }
```

---

## Environment Configuration

```
.env File
├─ Delinea Configuration
│  ├─ DELINEA_API_BASE=https://cookiejar.delinea.app
│  ├─ DELINEA_CLIENT_ID=dhruvap@cookiejar
│  ├─ DELINEA_CLIENT_SECRET=GoldGreen@21
│  └─ DELINEA_OAUTH_TOKEN= (optional)
│
├─ Webhook Configuration
│  ├─ PORT=9090
│  ├─ HMAC_SECRET=local_test_secret
│  └─ HMAC_REQUIRED=true
│
├─ Zoho Configuration
│  ├─ ZOHO_API_BASE=http://localhost:19001
│  ├─ ZOHO_CLIENT_ID=mock
│  └─ ZOHO_CLIENT_SECRET=mock
│
└─ Approval Configuration
   ├─ APPROVAL_REGEX=^\s*(\/?approve|approved|ack|ok|accepted|✅)
   ├─ SENIOR_APPROVERS=alice@example.com,bob@example.com
   ├─ REVOKE_WORKER_INTERVAL_SECONDS=60
   └─ GRANTS_STORE=grants.jsonl
```

---

## Error Handling Decision Tree

```
Request Received
├─ HMAC Valid?
│  ├─ NO → Response 401 Unauthorized
│  └─ YES → Continue
│
├─ Approval Keywords Match?
│  ├─ NO → Response 400 Bad Request
│  └─ YES → Continue
│
├─ Approver Authorized?
│  ├─ NO → Response 403 Forbidden
│  └─ YES → Continue
│
├─ Can Get Delinea Token?
│  ├─ NO → Response 400 (Auth failed)
│  └─ YES → Continue
│
├─ Privilege Escalation Successful?
│  ├─ 200 OK → Grant Created ✅
│  ├─ 409 Conflict → Already Escalated ✅ (Idempotent)
│  ├─ 4xx/5xx → Response 400 (Error)
│  └─ Network Error → Response 500
│
└─ Response 200 OK {"result": "ok"}
```

---

This diagram shows the complete end-to-end flow of the Delinea Privilege Escalation integration.
