import httpx
import json
import tiktoken
from fastapi import HTTPException
from app.config import settings
from app.sanitizer import sanitize_text, sanitize_tool_arguments, desanitize_text, PolicyBlockedException

client = httpx.AsyncClient(timeout=120.0) 
tokenizer = tiktoken.get_encoding("cl100k_base") 

def count_tokens(text: str) -> int:
    return len(tokenizer.encode(text))

def select_model(prompt: str) -> str:
    prompt_lower = prompt.lower()
    reasoning_keywords = ["analyze", "think", "solve", "logic", "reason", "step-by-step", "math", "complex"]
    
    if any(keyword in prompt_lower for keyword in reasoning_keywords):
        print(f"[Router] Routing to REASONING model.")
        return settings.MODEL_REASONING
    else:
        print(f"[Router] Routing to FAST model.")
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
            
            # 1. Token Guard
            full_text = " ".join([m.get("content", "") if isinstance(m.get("content"), str) else "" for m in data.get("messages", [])])
            if count_tokens(full_text) > settings.MAX_INPUT_TOKENS:
                raise HTTPException(status_code=400, detail="Input too large.")

            # 2. Force Free Models
            data["model"] = select_model(full_text)

            # 3. Sanitization
            if "messages" in data:
                # Inject System Instruction
                system_instruction = {
                    "role": "system",
                    "content": "CRITICAL: Preserve placeholders like <PERSON_123> exactly."
                }
                data["messages"].insert(0, system_instruction)

                for message in data["messages"]:
                    # A. Sanitize Content (Standard Chat)
                    if isinstance(message.get("content"), str):
                        message["content"] = sanitize_text(message["content"])
                    
                    # B. Sanitize Tool Calls (Agent Support)
                    if "tool_calls" in message:
                        for tool_call in message["tool_calls"]:
                            if "function" in tool_call and "arguments" in tool_call["function"]:
                                args_str = tool_call["function"]["arguments"]
                                # USE THE NEW RECURSIVE SCRUBBER
                                scrubbed_args = sanitize_tool_arguments(args_str)
                                tool_call["function"]["arguments"] = scrubbed_args
                                print("[QuiGuard] Sanitized Agent Tool Call arguments.")

                print(f"[QuiGuard] Secure payload sent to {data['model']}.")
                body = json.dumps(data).encode('utf-8')
                
        except PolicyBlockedException as e:
            print(f"!!! [QuiGuard] REQUEST BLOCKED: {e}")
            raise HTTPException(status_code=403, detail=str(e))
            
        except Exception as e:
            print(f"!!! [QuiGuard] CRITICAL ERROR: {e}")
            raise HTTPException(status_code=500, detail=f"Internal Proxy Error: {str(e)}")

    response = await client.request(method=method, url=url, headers=final_headers, content=body)
    
    if response.status_code >= 400:
        print(f"\n!!! UPSTREAM ERROR ({response.status_code}) !!!")
        print(response.text[:200])

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