# 🛡️ QuiGuard: The AI Agent Firewall

QuiGuard is a self-hosted API gateway that acts as a security firewall for Large Language Models (LLMs) and AI Agents. It ensures sensitive data (PII, IP, Secrets) never leaves your network.

---

## 🚀 The Problem: "Agent Data Sprawl"

We are moving from "Chatbots" to "Agents". Agents don't just talk — they execute actions. This creates a new security risk:

- **Prompt Leaks:** Users paste API keys into prompts.
- **Tool Call Leaks:** Agents read internal tickets/emails and send that data to external models.

**QuiGuard fixes this.** It sits between your agents and the LLM provider, sanitizing data in real-time.

---

## ✨ Features

- 🔧 **Tool Call Scrubbing** *(New)*: The first proxy to intercept and sanitize Agent Tool Arguments. Stops agents from leaking data via API calls.
- 🔍 **Prompt Sanitization**: Detects and redacts PII (Emails, Phones, SSNs, Credit Cards) using [Microsoft Presidio](https://github.com/microsoft/presidio).
- 🚧 **Agent Guardrails**: Block dangerous actions (`DROP TABLE`) and domains (`competitor.com`).
- ⚙️ **Policy Modes**:
  - `Mask` — Redact sensitive data in place.
  - `Block` — Reject requests containing PII entirely.
  - `Warn` — Log warnings without blocking.
- 📋 **Audit Logs**: JSON audit trails for compliance (GDPR / HIPAA).
- 🧠 **Smart Routing**: Automatically routes queries to free/cheap models to save costs.
- 🏠 **Self-Hosted**: Runs in your VPC. No data ever leaves your servers.

---

## 🐳 Quick Start (Docker)

The fastest way to get QuiGuard running.

```bash
# 1. Clone the repository
git clone https://github.com/somegg90-blip/QuiGuard-gateway.git
cd QuiGuard-gateway

# 2. Configure Environment
echo "API_KEY=your_openrouter_key" > .env

# 3. Run
docker-compose up -d
```

Your proxy is now running at `http://localhost:8000`.

---

## ⚙️ Usage (Python)

Point your OpenAI client to the QuiGuard proxy URL.

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",  # Point to QuiGuard
    api_key="dummy_key"                   # QuiGuard manages the real key
)

response = client.chat.completions.create(
    model="auto",  # Let QuiGuard optimize the model
    messages=[{"role": "user", "content": "My email is test@test.com"}]
)

print(response.choices[0].message.content)
```

---

## 📖 Configuration

All security rules are defined in `policy.yaml`.

### Example: Block Mode

```yaml
action_mode: "block"
```

If PII is detected, the request is rejected with `403 Forbidden`.

### Example: Agent Guardrails

```yaml
agent_security:
  blocked_domains:
    - "competitor.com"
  blocked_patterns:
    - "DROP TABLE"
```

---

## 🛡️ Use Cases

| Use Case | Description |
|---|---|
| **Secure AI Agents** | Stop autonomous agents from leaking data via Tool Calls. |
| **Compliance** | Enforce GDPR/HIPAA data redaction automatically. |
| **Cost Control** | Use Smart Routing to avoid expensive model fees. |

---

## 📜 License

QuiGuard is released under the [MIT License](LICENSE).
