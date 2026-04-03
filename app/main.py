from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, Request, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from app.proxy import forward_request, process_response
from app.store import SessionStore
from app.auth_middleware import validate_api_key, check_rate_limit, create_api_key_for_user, list_api_keys_for_user, revoke_api_key
from app.config import settings, set_request_policy
import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

app = FastAPI(
    title="QuiGuard API",
    description="The Security Layer for AI. Redacts PII, enforces policies, and manages model routing.",
    version="2.0.0"
)

# Routes that should NOT require API key auth (public endpoints)
PUBLIC_PATHS = {"/health", "/api/audit-logs", "/api/audit-stats", "/api/keys", "/api/policy"}

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    async def cleanup_task():
        while True:
            SessionStore.cleanup()
            await asyncio.sleep(60)
    asyncio.create_task(cleanup_task())


# ============================================================
# Helper: Get Supabase client (server-side)
# ============================================================

def _get_supabase_client():
    try:
        from supabase import create_client
        supabase_url = os.getenv("SUPABASE_URL", "")
        supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        if not supabase_url or not supabase_key:
            return None
        return create_client(supabase_url, supabase_key)
    except Exception:
        return None


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


# ============================================================
# Phase 3: Secure Ledger - Audit Logs API
# ============================================================

@app.get("/api/audit-logs")
async def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    risk_only: bool = Query(False),
    hours: Optional[int] = Query(None),
    user_id: Optional[str] = Query(None),
):
    supabase = _get_supabase_client()

    if supabase is None:
        LOG_FILE = "audit_log.jsonl"
        logs = []

        if not os.path.exists(LOG_FILE):
            return JSONResponse(content={"logs": [], "total": 0})

        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]

                for line in lines:
                    if not line.strip():
                        continue
                    entry = json.loads(line)

                    if user_id and entry.get("user_id") != user_id:
                        continue

                    if event_type and entry.get("event") != event_type:
                        continue

                    if risk_only and not entry.get("risk_detected", False):
                        continue

                    secure_entry = {
                        "timestamp": entry.get("timestamp"),
                        "event": entry.get("event"),
                        "risk_detected": entry.get("risk_detected"),
                        "entities_blocked": entry.get("entities_blocked"),
                        "sanitized_snippet": entry.get("sanitized_snippet"),
                        "id": None
                    }
                    logs.append(secure_entry)

            return JSONResponse(content={"logs": logs, "total": len(logs)})

        except Exception as e:
            print(f"Error reading local logs: {e}")
            return JSONResponse(content={"error": "Failed to read logs"}, status_code=500)

    try:
        query = supabase.table("audit_logs").select(
            "id, timestamp, event, risk_detected, entities_blocked, sanitized_snippet",
            count="exact"
        )

        # >>> USER ISOLATION: Only return this user's logs <<<
        if user_id:
            query = query.eq("user_id", user_id)

        if event_type:
            query = query.eq("event", event_type)

        if risk_only:
            query = query.eq("risk_detected", True)

        if hours:
            cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            query = query.gte("timestamp", cutoff)

        query = query.order("timestamp", desc=True)
        query = query.range(offset, offset + limit - 1)

        response = query.execute()

        logs = []
        for row in response.data:
            logs.append({
                "id": row.get("id"),
                "timestamp": row.get("timestamp"),
                "event": row.get("event"),
                "risk_detected": row.get("risk_detected"),
                "entities_blocked": row.get("entities_blocked", []),
                "sanitized_snippet": row.get("sanitized_snippet"),
            })

        total = response.count if hasattr(response, 'count') else len(logs)

        return JSONResponse(content={
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset,
        })

    except Exception as e:
        print(f"[Audit API] Error reading from Supabase: {e}")
        return JSONResponse(content={"error": "Failed to read logs"}, status_code=500)


@app.get("/api/audit-stats")
async def get_audit_stats(
    hours: int = Query(24, ge=1, le=720, description="Stats for the last N hours"),
    user_id: Optional[str] = Query(None),
):
    supabase = _get_supabase_client()

    if supabase is None:
        LOG_FILE = "audit_log.jsonl"
        if not os.path.exists(LOG_FILE):
            return JSONResponse(content={
                "total_events": 0,
                "blocked": 0,
                "sanitized": 0,
                "top_entities": [],
                "events_over_time": [],
            })

        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            entries = []

            with open(LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    if user_id and entry.get("user_id") != user_id:
                        continue
                    try:
                        ts = datetime.fromisoformat(entry.get("timestamp", ""))
                        if ts >= cutoff:
                            entries.append(entry)
                    except (ValueError, TypeError):
                        continue

            total = len(entries)
            blocked = sum(1 for e in entries if e.get("event") == "request_blocked")
            sanitized = sum(1 for e in entries if e.get("event") == "prompt_sanitized")

            entity_counts = {}
            for e in entries:
                for ent in e.get("entities_blocked", []):
                    entity_counts[ent] = entity_counts.get(ent, 0) + 1
            top_entities = sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            hourly = {}
            for e in entries:
                try:
                    ts = datetime.fromisoformat(e.get("timestamp", ""))
                    hour_key = ts.strftime("%Y-%m-%dT%H:00:00")
                    hourly[hour_key] = hourly.get(hour_key, 0) + 1
                except (ValueError, TypeError):
                    continue

            events_over_time = [{"hour": k, "count": v} for k, v in sorted(hourly.items())]

            return JSONResponse(content={
                "total_events": total,
                "blocked": blocked,
                "sanitized": sanitized,
                "top_entities": top_entities,
                "events_over_time": events_over_time,
            })

        except Exception as e:
            print(f"[Audit Stats] Local file error: {e}")
            return JSONResponse(content={"error": "Failed to compute stats"}, status_code=500)

    try:
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        # >>> USER ISOLATION on all queries <<<
        base_query = supabase.table("audit_logs").select(
            "id", count="exact"
        ).gte("timestamp", cutoff)
        if user_id:
            base_query = base_query.eq("user_id", user_id)
        total_response = base_query.execute()
        total_events = total_response.count if hasattr(total_response, 'count') else len(total_response.data)

        blocked_query = supabase.table("audit_logs").select(
            "id", count="exact"
        ).gte("timestamp", cutoff).eq("event", "request_blocked")
        if user_id:
            blocked_query = blocked_query.eq("user_id", user_id)
        blocked_response = blocked_query.execute()
        blocked = blocked_response.count if hasattr(blocked_response, 'count') else len(blocked_response.data)

        sanitized_query = supabase.table("audit_logs").select(
            "id", count="exact"
        ).gte("timestamp", cutoff).eq("event", "prompt_sanitized")
        if user_id:
            sanitized_query = sanitized_query.eq("user_id", user_id)
        sanitized_response = sanitized_query.execute()
        sanitized = sanitized_response.count if hasattr(sanitized_response, 'count') else len(sanitized_response.data)

        all_query = supabase.table("audit_logs").select(
            "timestamp, entities_blocked, event"
        ).gte("timestamp", cutoff).order("timestamp", desc=True)
        if user_id:
            all_query = all_query.eq("user_id", user_id)
        all_response = all_query.execute()

        entity_counts = {}
        for row in all_response.data:
            for ent in row.get("entities_blocked", []):
                entity_counts[ent] = entity_counts.get(ent, 0) + 1
        top_entities = sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        hourly = {}
        for row in all_response.data:
            try:
                ts = row.get("timestamp", "")
                if ts:
                    if isinstance(ts, str):
                        ts = ts.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts)
                    hour_key = dt.strftime("%Y-%m-%dT%H:00:00")
                    hourly[hour_key] = hourly.get(hour_key, 0) + 1
            except (ValueError, TypeError):
                continue

        events_over_time = [{"hour": k, "count": v} for k, v in sorted(hourly.items())]

        return JSONResponse(content={
            "total_events": total_events,
            "blocked": blocked,
            "sanitized": sanitized,
            "top_entities": top_entities,
            "events_over_time": events_over_time,
        })

    except Exception as e:
        print(f"[Audit Stats] Supabase error: {e}")
        return JSONResponse(content={"error": "Failed to compute stats"}, status_code=500)


# ============================================================
# Phase 4: Subscription Endpoint
# ============================================================

@app.get("/api/subscription")
async def get_subscription(user_id: str):
    supabase = _get_supabase_client()
    if supabase is None:
        return JSONResponse(content={"error": "Supabase not configured"}, status_code=500)

    try:
        response = supabase.table("subscriptions").select(
            "plan, status, monthly_request_count, monthly_request_limit, max_seats, max_api_keys, log_retention_days, current_period_start, current_period_end, trial_ends_at, created_at"
        ).eq("user_id", user_id).limit(1).execute()

        if not response.data:
            return JSONResponse(content={"error": "No subscription found"}, status_code=404)

        return JSONResponse(content=response.data[0])
    except Exception as e:
        print(f"[Subscription] Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ============================================================
# Phase 4: API Key Management Endpoints
# ============================================================

class CreateKeyRequest(BaseModel):
    user_id: str
    name: str = "Default Key"

@app.post("/api/keys/create")
async def create_key(req: CreateKeyRequest):
    result = create_api_key_for_user(req.user_id, req.name)

    if result and "error" in result:
        return JSONResponse(content=result, status_code=400)

    if result is None:
        return JSONResponse(content={"error": "Failed to create key"}, status_code=500)

    return JSONResponse(content=result, status_code=201)

@app.get("/api/keys")
async def list_keys(user_id: str):
    keys = list_api_keys_for_user(user_id)
    return JSONResponse(content={"keys": keys})

@app.delete("/api/keys/{key_id}")
async def delete_key(key_id: int, user_id: str):
    success = revoke_api_key(key_id, user_id)
    if not success:
        return JSONResponse(content={"error": "Key not found or already revoked"}, status_code=404)
    return JSONResponse(content={"message": "API key revoked successfully"})


# ============================================================
# Phase 4 Step 3: Policy Editor API
# ============================================================

@app.get("/api/policy")
async def get_policy(user_id: str):
    try:
        merged_policy = settings.load_user_policy(user_id)
        return JSONResponse(content={"policy": merged_policy})
    except Exception as e:
        print(f"[Policy API] Error: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


class SavePolicyRequest(BaseModel):
    user_id: str
    policy: dict

@app.put("/api/policy")
async def save_policy(req: SavePolicyRequest):
    try:
        result = settings.save_user_policy(req.user_id, req.policy)
        return JSONResponse(content=result, status_code=200)
    except Exception as e:
        print(f"[Policy API] Error saving: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.delete("/api/policy")
async def reset_policy(user_id: str):
    try:
        result = settings.reset_user_policy(user_id)
        return JSONResponse(content=result, status_code=200)
    except Exception as e:
        print(f"[Policy API] Error resetting: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ============================================================
# Phase 4: Protected Proxy Route (with API Key Auth)
# ============================================================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    full_path = f"/{path}"

    if full_path.startswith("/api/"):
        return JSONResponse(content={"error": "Not found"}, status_code=404)

    # 2. Validate API Key
    api_key = request.headers.get("Authorization", "").replace("Bearer ", "")
    api_key = api_key or request.headers.get("X-QuiGuard-Key", "")

    key_info = validate_api_key(api_key)

    if key_info is None:
        return JSONResponse(
            content={
                "error": {
                    "message": "Invalid or missing API key.",
                    "code": "AUTH_INVALID_KEY",
                    "docs": "https://quiguard.ai/docs/api-keys"
                }
            },
            status_code=401
        )

    # Load user-specific policy for this request
    user_id = key_info.get('user_id') if isinstance(key_info, dict) else getattr(key_info, 'user_id', None)
    if user_id:
        try:
            user_policy = settings.load_user_policy(user_id)
            set_request_policy(user_policy)
        except Exception as e:
            print(f"[Proxy] Error loading user policy: {e}")

    # 3. Check Rate Limit
    allowed, message = check_rate_limit(key_info)
    if not allowed:
        return JSONResponse(
            content={
                "error": {
                    "message": message,
                    "code": "RATE_LIMIT_EXCEEDED",
                    "plan": key_info.plan,
                    "docs": "https://quiguard.ai/pricing"
                }
            },
            status_code=429
        )

    # 4. Read Request
    body = await request.body()
    headers = dict(request.headers)

    # 5. Forward & Sanitize
    try:
        upstream_response = await forward_request(
            method=request.method,
            path=path,
            headers=headers,
            body=body
        )
    except HTTPException as e:
        return JSONResponse(
            content={"error": {"message": e.detail, "code": "PROXY_ERROR"}},
            status_code=e.status_code
        )

    # 6. Process & Desanitize
    final_body = await process_response(upstream_response, path)

    # 7. Filter Headers
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding']
    response_headers = {
        k: v for k, v in upstream_response.headers.items()
        if k.lower() not in excluded_headers
    }

    # 8. Add usage headers
    response_headers["X-QuiGuard-Plan"] = key_info.plan
    response_headers["X-QuiGuard-Usage"] = message

    # 9. Return
    return Response(
        content=final_body,
        status_code=upstream_response.status_code,
        headers=response_headers
    )