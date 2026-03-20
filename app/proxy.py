import httpx
import json
import tiktoken
import re
from fastapi import HTTPException
from app.config import settings
from app.sanitizer import sanitize_text, desanitize_text, PolicyBlockedException

client = httpx.AsyncClient(timeout=120.0) 
tokenizer = tiktoken.get_encoding("cl100k_base") 

def count_tokens(text: str) -> int:
    return len(tokenizer.encode(text))

def select_model(prompt: str) -> str:
    """
    Smart Router: Decides which free model to use.
    """
    prompt_lower = prompt.lower()
    reasoning_keywords = ["analyze", "think", "solve", "logic", "reason", "step-by-step", "explain why", "math", "complex"]
    
    if any(keyword in prompt_lower for keyword in reasoning_keywords):
        print(f"[Router] Routing to REASONING model (Nemotron).")
        return settings.MODEL_REASONING
    else:
        print(f"[Router] Routing to FAST model (Llama/Arcee).")
        return settings.MODEL_FAST

async def forward_request(method: str, path: str, headers: dict, body: bytes):
    url = f"{settings.base_url}/{path}"
    
    headers.pop('host', None)
    headers.pop('content-length', None)
    headers.pop('authorization', None) 

    final_headers = {
        "Authorization": f"Bearer {settings.API_KEY}",
        "Content-Type": "application/json",
        **settings.headers
    }
    
    final_headers.update(headers)

    if "chat/completions" in path and body:
        try:
            data = json.loads(body)
            
            # --- 1. TOKEN GUARD ---
            full_text = " ".join([m.get("content", "") for m in data.get("messages", [])])
            token_count = count_tokens(full_text)
            
            if token_count > settings.MAX_INPUT_TOKENS:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Security Alert: Input too large ({token_count} tokens). Limit is {settings.MAX_INPUT_TOKENS}."
                )

            # --- 2. ENFORCE FREE MODELS (Cost Control) ---
            # We ignore whatever model the user asked for and FORCE a free one.
            # This guarantees $0 cost.
            data["model"] = select_model(full_text)

            # --- 3. REASONING MODEL CONFIG ---
            if "nemotron" in data["model"]:
                data["reasoning"] = {"enabled": True}
                print("[Config] Enabled Reasoning Mode.")

            # --- 4. OUTPUT TOKEN LIMIT ---
            if "max_tokens" not in data:
                data["max_tokens"] = settings.MAX_OUTPUT_TOKENS

            # --- 5. SANITIZATION ---
            if "messages" in data:
                # Inject System Instruction
                system_instruction = {
                    "role": "system",
                    "content": "CRITICAL SECURITY INSTRUCTION: You must preserve all placeholders (e.g., <SECRET_123>) exactly as written."
                }
                data["messages"].insert(0, system_instruction)

                for message in data["messages"]:
                    if "CRITICAL SECURITY INSTRUCTION" in message.get("content", ""):
                        continue
                    if isinstance(message.get("content"), str):
                        message["content"] = sanitize_text(message["content"])

                print(f"[IronLayer] Secure payload sent to {data['model']}.")
                body = json.dumps(data).encode('utf-8')
                
        except PolicyBlockedException as e:
            # Handle the Block Mode
            print(f"!!! [IronLayer] REQUEST BLOCKED: {e}")
            raise HTTPException(status_code=403, detail=str(e))
            
        except Exception as e:
            print(f"!!! [IronLayer] CRITICAL ERROR: {e}")
            raise HTTPException(status_code=500, detail=f"Internal Proxy Error: {str(e)}")

    response = await client.request(
        method=method,
        url=url,
        headers=final_headers,
        content=body
    )
    
    if response.status_code >= 400:
        print(f"\n!!! UPSTREAM ERROR ({response.status_code}) !!!")
        print(response.text[:500]) 
        print("!!! END ERROR !!!\n")

    return response

async def process_response(response: httpx.Response, path: str):
    if response.status_code == 200 and "chat/completions" in path:
        try:
            data = response.json()
            
            if "choices" in data:
                for choice in data["choices"]:
                    if "message" in choice and "content" in choice["message"]:
                        choice["message"]["content"] = desanitize_text(choice["message"]["content"])
            
            return json.dumps(data).encode('utf-8')
        except Exception as e:
            print(f"Error desanitizing: {e}")
            return response.content
    
    return response.content