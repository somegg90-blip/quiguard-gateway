🛡️ IronLayer: The Self-Hosted Security Layer for AI
https://opensource.org/license/MIT https://www.docker.com/ https://www.python.org/

IronLayer is an API-first security gateway that acts as a firewall for Large Language Models (LLMs) and AI Agents. It sits between your applications and AI providers (OpenAI, Anthropic, Groq, etc.) to prevent data leaks, enforce security policies, and optimize costs.

🚀 Key Features
PII Scrubbing: Automatically detects and redacts sensitive data (Emails, Credit Cards, SSNs, Crypto Wallets, Medical Licenses) before it leaves your network.
IP Protection: Define custom regex patterns to protect internal project names, API keys, and employee IDs.
Agent Guardrails: Block dangerous actions (e.g., DROP TABLE, DELETE) and prevent data exfiltration to blocked domains.
Smart Routing: Automatically routes complex queries to powerful "Reasoning" models (Nemotron) and simple queries to fast, cheap models (Llama/Qwen) to optimize performance and cost.
Cost Control: Enforces token limits to prevent "runaway" AI usage and unexpected bills.
Round-Trip Restoration: Users see clean, readable data; the AI sees only scrubbed placeholders. The process is invisible to the end-user.
🏗️ How It Works
IronLayer acts as a transparent "Man-in-the-Middle" (The Good Kind).

Intercept: Your application sends a prompt to IronLayer (running locally or in your VPC).
Analyze: IronLayer scans the prompt for PII and security violations.
Scrub: Sensitive data is replaced with placeholders (e.g., boss@company.com → <EMAIL_ADDRESS_123>).
Route: The clean prompt is forwarded to the appropriate AI provider.
Restore: The AI's response is received, placeholders are swapped back for real data, and the final result is returned to the user.
🐳 Quick Start (Docker)
The fastest way to get IronLayer running.

1. Clone the repository

git clone https://github.com/somegg90-blip/ironlayer-gateway.gitcd ironlayer-gateway
2. Configure Environment
Create a .env file with your AI provider key:

text

PROVIDER=openrouter
API_KEY=sk-or-v1-your_key_here
3. Run with Docker Compose

bash

docker-compose up -d
4. Send Traffic
Point your OpenAI client to http://localhost:8000/v1 instead of the default OpenAI URL.

⚙️ Configuration
All security rules and routing logic are defined in policy.yaml. You can update this file without restarting the server.

Example policy.yaml
yaml

# PII Detection
pii:
  enabled: true
  entities:
    - EMAIL_ADDRESS
    - CREDIT_CARD
    - CRYPTO
    - MEDICAL_LICENSE

# Custom Secrets (IP Protection)
custom_patterns:
  - name: "PROJECT_STARLIGHT"
    regex: "ProjectStarlight|Starlight-Initiative"
    score: 0.9
    context: ["project", "deadline"]

# Agent Guardrails
agent_security:
  blocked_domains:
    - "competitor.com"
  blocked_patterns:
    - "DROP TABLE"
📖 Usage Examples
cURL
bash

curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto",
    "messages": [{"role": "user", "content": "My email is test@test.com."}]
  }'
Python (OpenAI SDK)
python

from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1", # Point to IronLayer
    api_key="dummy_key" # IronLayer handles the real key
)

response = client.chat.completions.create(
    model="auto", # Let IronLayer decide the best model
    messages=[{"role": "user", "content": "My email is test@test.com."}]
)

print(response.choices[0].message.content)
🛡️ Use Cases
Enterprise Security: Ensure employees don't inadvertently leak PII or trade secrets to public AI models.
AI Agent Safety: Prevent autonomous agents from executing dangerous code or accessing unauthorized resources.
Compliance: Enforce GDPR/HIPAA data redaction automatically for all AI interactions.
Cost Optimization: Use Smart Routing to avoid using expensive models for simple tasks.
🗺️ Roadmap
 Web Dashboard: UI for viewing audit logs and managing policies.
 RBAC: Role-based access control for teams.
 Streaming Support: Full support for streaming API responses.
 More Providers: Native support for Azure OpenAI and AWS Bedrock.
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingFeature)
Commit your Changes (git commit -m 'Add some AmazingFeature')
Push to the Branch (git push origin feature/AmazingFeature)
Open a Pull Request
📄 License
Distributed under the MIT License. 