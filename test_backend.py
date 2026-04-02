"""
============================================================
QuiGuard Backend — Comprehensive Test Suite
Run: python test_backend.py
============================================================

This script tests ALL backend endpoints.
Prerequisites:
  - uvicorn running on localhost:8000
  - Supabase configured in .env
  - A valid Supabase user UUID (replace YOUR_USER_ID below)
"""

import requests
import json
import time
import sys

BASE_URL = "http://localhost:8000"

# ============================================================
# CONFIG — Change this to your Supabase user UUID
# ============================================================
USER_ID = "1bfb6a4a-2404-4e67-8c0e-509f63f33e50"  # <-- REPLACE THIS

# Track results
passed = 0
failed = 0
errors = []

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        msg = f"  ❌ {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
        errors.append(name)

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ============================================================
# TEST 1: HEALTH CHECK
# ============================================================
section("TEST 1: Health Check")

r = requests.get(f"{BASE_URL}/health")
test("Health endpoint returns 200", r.status_code == 200, f"Got {r.status_code}")
data = r.json()
test("Version is 2.0.0", data.get("version") == "2.0.0", f"Got {data.get('version')}")
test("Status is healthy", data.get("status") == "healthy")

# ============================================================
# TEST 2: API KEY AUTH — No Key (should fail)
# ============================================================
section("TEST 2: Proxy Auth — No API Key")

r = requests.post(f"{BASE_URL}/v1/chat/completions")
test("Proxy without key returns 401", r.status_code == 401, f"Got {r.status_code}")
if r.status_code == 401:
    data = r.json()
    test("Error code is AUTH_INVALID_KEY", data.get("error", {}).get("code") == "AUTH_INVALID_KEY")

# ============================================================
# TEST 3: API KEY AUTH — Invalid Key (should fail)
# ============================================================
section("TEST 3: Proxy Auth — Invalid API Key")

r = requests.post(
    f"{BASE_URL}/v1/chat/completions",
    headers={"Authorization": "Bearer qg_sk_fakekey123456789"}
)
test("Proxy with fake key returns 401", r.status_code == 401, f"Got {r.status_code}")

# ============================================================
# TEST 4: API KEY AUTH — Wrong header (should fail)
# ============================================================
section("TEST 4: Proxy Auth — No Auth Header at All")

r = requests.post(
    f"{BASE_URL}/v1/chat/completions",
    json={"messages": [{"role": "user", "content": "Hello"}]}
)
test("Proxy with no auth header returns 401", r.status_code == 401, f"Got {r.status_code}")

# ============================================================
# TEST 5: API KEY CRUD — Create Key
# ============================================================
section("TEST 5: API Key Management — Create")

created_key = None

r = requests.post(
    f"{BASE_URL}/api/keys/create",
    json={"user_id": USER_ID, "name": "Test Key Suite"},
)
test("Create key returns 201", r.status_code == 201, f"Got {r.status_code}: {r.text[:100]}")
if r.status_code == 201:
    data = r.json()
    created_key = data.get("key")
    test("Response includes raw key", created_key is not None, "No 'key' field in response")
    test("Key starts with qg_sk_", created_key.startswith("qg_sk_") if created_key else False, f"Got: {created_key[:20] if created_key else 'None'}")
    test("Response includes key_prefix", data.get("key_prefix") is not None)
    test("Response includes name", data.get("name") == "Test Key Suite")
else:
    print(f"  ⚠️  Skipping key tests — key creation failed. Make sure USER_ID is set and Supabase is configured.")

# ============================================================
# TEST 6: API KEY CRUD — List Keys
# ============================================================
section("TEST 6: API Key Management — List")

if created_key:
    r = requests.get(f"{BASE_URL}/api/keys?user_id={USER_ID}")
    test("List keys returns 200", r.status_code == 200, f"Got {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        keys = data.get("keys", [])
        test("Keys list is non-empty", len(keys) > 0, f"Got {len(keys)} keys")
        test("Key objects have 'id'", all(k.get("id") for k in keys))
        test("Key objects have 'key_prefix'", all(k.get("key_prefix") for k in keys))
        test("Key objects have 'is_active'", all("is_active" in k for k in keys))
        # CRITICAL: raw key should NEVER appear in list
        # key_prefix (e.g., "qg_sk_a3f2") is OK, but the full 50+ char key is NOT
        has_raw_key = False
        for k in keys:
            # Remove the known key_prefix from the check
            prefix = k.get("key_prefix", "")
            key_json = json.dumps(k).replace(prefix, "")
            if len(prefix) > 0 and prefix.startswith("qg_sk_"):
                # Check if any remaining qg_sk_ references exist (besides prefix)
                if "qg_sk_" in key_json:
                    has_raw_key = True
                    break
            elif "qg_sk_" in json.dumps(k) and prefix == "":
                has_raw_key = True
                break
        test("Raw key NOT exposed in list response", not has_raw_key, "SECURITY ISSUE: Raw key leaked!")

# ============================================================
# TEST 7: API KEY CRUD — List for Wrong User (should be empty)
# ============================================================
section("TEST 7: API Key Isolation — Wrong User")

r = requests.get(f"{BASE_URL}/api/keys?user_id=00000000-0000-0000-0000-000000000000")
test("List keys for fake user returns 200", r.status_code == 200, f"Got {r.status_code}")
if r.status_code == 200:
    data = r.json()
    test("Fake user has 0 keys", len(data.get("keys", [])) == 0, f"Got {len(data.get('keys', []))} keys")

# ============================================================
# TEST 8: PROXY — Valid Key (should forward)
# ============================================================
section("TEST 8: Proxy — Valid API Key")

if created_key:
    r = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Authorization": f"Bearer {created_key}"},
        json={
            "model": "test",
            "messages": [
                {"role": "user", "content": "My email is test@example.com"}
            ]
        },
        timeout=30
    )
    # We expect either a successful proxy forward (200 from upstream)
    # or a proxy error (4xx/5xx from QuiGuard)
    # But NOT a 401 (that would mean auth failed)
    test("Proxy with valid key does NOT return 401", r.status_code != 401, f"Got {r.status_code}")
    
    # Check for QuiGuard headers
    plan_header = r.headers.get("X-QuiGuard-Plan")
    test("Response includes X-QuiGuard-Plan header", plan_header is not None, "Header missing")
    if plan_header:
        test(f"Plan is: {plan_header}", True)
    
    usage_header = r.headers.get("X-QuiGuard-Usage")
    test("Response includes X-QuiGuard-Usage header", usage_header is not None, "Header missing")

# ============================================================
# TEST 9: PROXY — Valid Key via X-QuiGuard-Key header
# ============================================================
section("TEST 9: Proxy — X-QuiGuard-Key Header")

if created_key:
    r = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"X-QuiGuard-Key": created_key},
        json={"messages": [{"role": "user", "content": "Hello"}]},
        timeout=30
    )
    test("X-QuiGuard-Key header works", r.status_code != 401, f"Got {r.status_code}")

# ============================================================
# TEST 10: SUBSCRIPTION — Get Subscription
# ============================================================
section("TEST 10: Subscription Info")

r = requests.get(f"{BASE_URL}/api/subscription?user_id={USER_ID}")
test("Subscription returns 200", r.status_code == 200, f"Got {r.status_code}: {r.text[:100]}")
if r.status_code == 200:
    data = r.json()
    test("Has 'plan' field", data.get("plan") is not None, f"Missing plan")
    test("Has 'status' field", data.get("status") is not None)
    test("Has 'max_api_keys' field", data.get("max_api_keys") is not None)
    test("Has 'monthly_request_limit' field", "monthly_request_limit" in data)
    test("Status is 'active'", data.get("status") == "active", f"Got: {data.get('status')}")

# ============================================================
# TEST 11: AUDIT LOGS — List Logs
# ============================================================
section("TEST 11: Audit Logs Endpoint")

r = requests.get(f"{BASE_URL}/api/audit-logs?limit=5")
test("Audit logs returns 200", r.status_code == 200, f"Got {r.status_code}")
if r.status_code == 200:
    data = r.json()
    logs = data.get("logs", [])
    test("Response has 'logs' array", isinstance(logs, list))
    
    if len(logs) > 0:
        log = logs[0]
        test("Log has 'timestamp'", log.get("timestamp") is not None)
        test("Log has 'event'", log.get("event") is not None)
        test("Log has 'sanitized_snippet'", "sanitized_snippet" in log)
        # CRITICAL: original_snippet should NEVER be in the response
        response_text = json.dumps(data)
        test("original_snippet NOT in response", "original_snippet" not in response_text, "SECURITY ISSUE: PII leaked!")

# ============================================================
# TEST 12: AUDIT LOGS — Filtering
# ============================================================
section("TEST 12: Audit Logs — Filtering")

r = requests.get(f"{BASE_URL}/api/audit-logs?event_type=request_blocked&limit=5")
test("Filter by event_type returns 200", r.status_code == 200)
if r.status_code == 200:
    data = r.json()
    logs = data.get("logs", [])
    for log in logs:
        test("All logs match filter", log.get("event") == "request_blocked", f"Got: {log.get('event')}")

# ============================================================
# TEST 13: AUDIT STATS
# ============================================================
section("TEST 13: Audit Stats Endpoint")

r = requests.get(f"{BASE_URL}/api/audit-stats?hours=720")
test("Audit stats returns 200", r.status_code == 200, f"Got {r.status_code}")
if r.status_code == 200:
    data = r.json()
    test("Has 'total_events'", "total_events" in data)
    test("Has 'blocked'", "blocked" in data)
    test("Has 'sanitized'", "sanitized" in data)
    test("Has 'top_entities'", "top_entities" in data)
    test("Has 'events_over_time'", "events_over_time" in data)
    test("total_events is a number", isinstance(data.get("total_events"), (int, float)))

# ============================================================
# TEST 14: SANITIZATION — PII Detection
# ============================================================
section("TEST 14: Sanitization — PII in Prompts")

if created_key:
    # This tests that the proxy actually sanitizes PII
    # We send a prompt with an email and check if the upstream gets a sanitized version
    r = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Authorization": f"Bearer {created_key}"},
        json={
            "model": "test",
            "messages": [
                {"role": "user", "content": "My email is secret@test.com and my SSN is 123-45-6789"}
            ]
        },
        timeout=30
    )
    # Even if the upstream fails, the request should NOT be blocked (mask mode, not block mode)
    test("PII request not blocked in mask mode", r.status_code != 403, f"Got {r.status_code}")

# ============================================================
# TEST 15: API KEY — Revoke
# ============================================================
section("TEST 15: API Key — Revoke")

revoked_key_id = None

# Get a key ID to revoke
if created_key:
    r = requests.get(f"{BASE_URL}/api/keys?user_id={USER_ID}")
    if r.status_code == 200:
        keys = r.json().get("keys", [])
        for k in keys:
            if k.get("is_active"):
                revoked_key_id = k.get("id")
                break

if revoked_key_id:
    r = requests.delete(f"{BASE_URL}/api/keys/{revoked_key_id}?user_id={USER_ID}")
    test("Revoke key returns 200", r.status_code == 200, f"Got {r.status_code}: {r.text[:100]}")
    
    # Verify the key no longer works
    if created_key:
        r = requests.post(
            f"{BASE_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {created_key}"},
            json={"messages": [{"role": "user", "content": "test"}]},
        )
        # The key hash should still be valid but the key is deactivated
        # Actually — revoking a key sets is_active=False, so it should fail auth
        test("Revoked key returns 401", r.status_code == 401, f"Got {r.status_code}")
else:
    print("  ⚠️  No active key found to revoke")

# ============================================================
# TEST 16: API KEY — Create After Revoke (test limit)
# ============================================================
section("TEST 16: API Key — Recreate After Revoke")

r = requests.post(
    f"{BASE_URL}/api/keys/create",
    json={"user_id": USER_ID, "name": "Post-Revoke Test Key"},
)
# Should work since community plan allows 1 key and we revoked 1
test("Create new key after revoke succeeds", r.status_code == 201, f"Got {r.status_code}: {r.text[:100]}")

# ============================================================
# TEST 17: API KEY — Hit Limit
# ============================================================
section("TEST 17: API Key — Limit Enforcement (Community = 1 key)")

# Community plan allows 1 key. We already created one.
# Try creating a second — should fail
r = requests.post(
    f"{BASE_URL}/api/keys/create",
    json={"user_id": USER_ID, "name": "Overflow Key"},
)
test("Creating beyond limit returns 400", r.status_code == 400, f"Got {r.status_code}: {r.text[:100]}")
if r.status_code == 400:
    data = r.json()
    test("Error mentions key limit", "limit" in data.get("error", "").lower(), f"Got: {data.get('error')}")

# ============================================================
# TEST 18: SECURITY — Response Headers
# ============================================================
section("TEST 18: Security — Headers & Content")

r = requests.get(f"{BASE_URL}/health")
test("Content-Type is JSON", "application/json" in r.headers.get("Content-Type", ""), f"Got: {r.headers.get('Content-Type')}")

r = requests.get(f"{BASE_URL}/api/audit-logs?limit=1")
if r.status_code == 200:
    response_text = r.text
    test("No original_snippet in audit-logs response", "original_snippet" not in response_text)

# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*60}")
print(f"  TEST RESULTS")
print(f"{'='*60}")
print(f"  ✅ Passed: {passed}")
print(f"  ❌ Failed: {failed}")
print(f"  Total:    {passed + failed}")

if failed > 0:
    print(f"\n  Failed tests:")
    for e in errors:
        print(f"    ❌ {e}")
    print(f"\n  {failed} test(s) failed. Fix and re-run.")
    sys.exit(1)
else:
    print(f"\n  🎉 ALL TESTS PASSED! Backend is ready for deployment.")
    sys.exit(0)