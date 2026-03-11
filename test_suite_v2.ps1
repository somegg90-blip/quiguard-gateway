Write-Host "--- IronLayer V2 Test Suite ---" -ForegroundColor Cyan

# Test 1: Advanced PII
Write-Host "`n[Test 1] Testing Advanced PII (Crypto/Medical)..." -ForegroundColor Yellow
 $body1 = @{
    model = "auto"
    messages = @(@{ role="user"; content="My Bitcoin wallet is 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa." })
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/chat/completions" -Method Post -Headers @{"Content-Type"="application/json"} -Body $body1 | Out-Null
Write-Host "Check logs above for: [IronLayer] Scrubbed... [CRYPTO]" -ForegroundColor Green

# Test 2: Smart Routing (Reasoning)
Write-Host "`n[Test 2] Testing Smart Routing (Reasoning)..." -ForegroundColor Yellow
 $body2 = @{
    model = "auto"
    messages = @(@{ role="user"; content="Solve this logic puzzle step by step." })
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/chat/completions" -Method Post -Headers @{"Content-Type"="application/json"} -Body $body2 | Out-Null
Write-Host "Check logs above for: [Router] Routing to REASONING model" -ForegroundColor Green

# Test 3: Guardrails
Write-Host "`n[Test 3] Testing Agent Guardrails (Blocked Domain)..." -ForegroundColor Yellow
 $body3 = @{
    model = "auto"
    messages = @(@{ role="user"; content="Go to competitor.com please." })
} | ConvertTo-Json -Depth 3
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/chat/completions" -Method Post -Headers @{"Content-Type"="application/json"} -Body $body3 | Out-Null
    Write-Host "ERROR: Guardrail failed to block request!" -ForegroundColor Red
} catch {
    Write-Host "SUCCESS: Request blocked by security policy." -ForegroundColor Green
}

Write-Host "`n--- Tests Complete ---" -ForegroundColor Cyan