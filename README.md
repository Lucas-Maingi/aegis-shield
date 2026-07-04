# Aegis Shield — LLM Security & Compliance Gateway

[![CI](https://github.com/Lucas-Maingi/aegis-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/Lucas-Maingi/aegis-shield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Aegis Shield is an enterprise-grade, low-latency security and compliance gateway designed to intercept, scan, and gate every request and completion before it travels between your client applications and upstream LLM providers (like OpenAI, Anthropic, or DeepSeek).

---

## 🏗️ Architecture & Flow

```
                      +-----------------------------+
                      |     Client Application      |
                      +--------------+--------------+
                                     |
                                     | OpenAI-Compatible Payload
                                     v
                      +--------------+--------------+
                      |        Aegis Shield         |
                      |        (FastAPI Proxy)      |
                      +---+---------------------+---+
                          |                     |
             1. Inbound   |                     | 3. Outbound
                Scanners  v                     v    Scanners
               +----------+---------+         +-----+--------------+
               |  - PII Leak        |         |  - API Key Leak    |
               |  - Jailbreak / DAN |         |  - Private IP/URL  |
               |  - System Prompt   |         |  - Refusal Bypass  |
               +----------+---------+         +-----+--------------+
                          |                         ^
                          | 2. Upstream Request     | 200 OK Response
                          v                         |
                      +---+-------------------------+---+
                      |      Upstream LLM Provider      |
                      |   (OpenAI, Anthropic, etc.)     |
                      +---------------------------------+
```

### Key Modules:
1.  **PII Scanner (`aegis_shield/scanners/pii.py`)**: A regex-based scanner verifying inputs against emails, phone numbers, SSNs, and credit cards (using the Luhn checksum algorithm to prevent false positives).
2.  **Prompt Injection Detector (`aegis_shield/scanners/injection.py`)**: Multi-layered scanner combining heuristic keyword matching for overrides, structural parsing for role tag injections, and Shannon entropy calculations for encoded attack vectors.
3.  **Output Scanner (`aegis_shield/scanners/output.py`)**: Intercepts the response to protect against system prompt leaks, private infrastructure leakage (local IPs/URLs), and jailbreak refusal bypass acknowledgements.
4.  **Token Bucket Limiter (`aegis_shield/limiter.py`)**: In-memory, lock-free token bucket rate-limiting per API key hash to defend against denial-of-service bill spikes.
5.  **Proxy Coordinator (`aegis_shield/app.py`)**: Exposes an OpenAI-compatible endpoint mapping `/v1/chat/completions`, supporting exact match caching in SQLite to respond to recurring questions in $<10\text{ms}$.

---

## 🛡️ Integration & Usage

Aegis Shield is designed to be a drop-in replacement for your model requests. It preserves standard OpenAI parameters so your existing SDK code works by simply overriding the `base_url`.

### Quickstart Setup:

```bash
# Clone the repository
git clone https://github.com/Lucas-Maingi/aegis-shield.git
cd aegis-shield

# Initialize venv and install package
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dashboard,dev]"
```

### 1. Launch the Gateway:
```bash
python -m uvicorn aegis_shield.app:app --host 0.0.0.0 --port 8000
```

### 2. Launch the Analytics Console:
```bash
streamlit run aegis_shield/dashboard.py
```

### 3. Deploy via Docker Compose:
```bash
docker-compose up --build
```
This boots both the gateway (port `8000`) and the security dashboard (port `8501`) sharing a unified database volume for metrics logs.

---

## 🔌 API Examples

### Proxy Request (Allowed):
```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my_openai_key" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "What is the capital of Kenya?"}]
  }'
```

### Proxy Request (Blocked - PII Leak):
```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Charging Visa card number 4111111111111111"}]
  }'
```

Response (HTTP 400):
```json
{
  "error": {
    "message": "Request blocked by Aegis Shield: Possible credit/debit card number detected (credit_card)",
    "type": "security_policy_violation",
    "request_id": "83cf92a182bd"
  }
}
```

---

## 🧪 Testing

Aegis Shield contains a robust test suite covering all modules.

```bash
# Run pytest with full verbosity
pytest tests/ -v
```

---

## 📝 License
MIT.
