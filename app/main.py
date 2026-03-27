from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.proxy import forward_request, process_response
from app.store import SessionStore
import asyncio
import json
import os

app = FastAPI(
    title="QuiGuard API",
    description="The Security Layer for AI. Redacts PII, enforces policies, and manages model routing.",
    version="1.0.0"
)

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
    # Cleanup task for expired keys
    async def cleanup_task():
        while True:
            SessionStore.cleanup()
            await asyncio.sleep(60)
    asyncio.create_task(cleanup_task())

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

# --- NEW: Phase 3 - The Secure Ledger ---

@app.get("/api/audit-logs")
async def get_audit_logs():
    """
    Securely retrieves the last N audit log entries.
    Strips 'original_snippet' to ensure PII never reaches the browser UI.
    """
    LOG_FILE = "audit_log.jsonl"
    limit = 100 # Return last 100 entries
    
    logs = []
    
    if not os.path.exists(LOG_FILE):
        return JSONResponse(content={"logs": []})

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            # Read lines efficiently from the end
            lines = f.readlines()[-limit:] 
            
            for line in lines:
                if not line.strip(): continue
                
                entry = json.loads(line)
                
                # SECURITY: Remove the raw PII before sending to frontend
                # We only keep the 'sanitized_snippet' and metadata
                secure_entry = {
                    "timestamp": entry.get("timestamp"),
                    "event": entry.get("event"),
                    "risk_detected": entry.get("risk_detected"),
                    "entities_blocked": entry.get("entities_blocked"),
                    "sanitized_snippet": entry.get("sanitized_snippet")
                }
                logs.append(secure_entry)
                
        return JSONResponse(content={"logs": logs})
        
    except Exception as e:
        print(f"Error reading logs: {e}")
        return JSONResponse(content={"error": "Failed to read logs"}, status_code=500)

# --- Existing Proxy Route ---

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    # 1. Read Request
    body = await request.body()
    headers = dict(request.headers)
    
    # 2. Forward & Sanitize
    upstream_response = await forward_request(
        method=request.method,
        path=path,
        headers=headers,
        body=body
    )
    
    # 3. Process & Desanitize
    final_body = await process_response(upstream_response, path)
    
    # 4. Filter Headers
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding']
    response_headers = {
        k: v for k, v in upstream_response.headers.items() 
        if k.lower() not in excluded_headers
    }
    
    # 5. Return
    return Response(
        content=final_body,
        status_code=upstream_response.status_code,
        headers=response_headers
    )