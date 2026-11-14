# 🛡 xhaqs-edge-shield-audit

Lightweight, zero-dependency **Edge Application Security & AI Guardrail Suite** engineered for Cloudflare Workers. Built specifically to audit and harden AI-assisted ("vibe-coded") web applications before production launch.

## 🔍 Core Capabilities

1. **Automated Secret Leak Scanner (`POST /scan`)**
   - Scans source files and payloads for exposed API keys and credentials (OpenAI, Anthropic, GitHub PATs, Supabase JWTs, AWS keys).
   - Flags exact line numbers, assigns severity levels, and redacts sensitive substrings in audit logs.
2. **AI Prompt Injection Guardrail (`POST /guard-ai`)**
   - Inspects incoming user prompts before they reach downstream LLM APIs.
   - Blocks system prompt extraction, instruction overrides, and jailbreak attempts with `403 Forbidden`.
3. **Edge Rate Limiter & Security Headers**
   - Enforces IP-based sliding-window rate limiting (`429 Too Many Requests`) to prevent API credit drain and brute-force abuse.
   - Automatically injects strict security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`) on all edge responses.

## 🚀 Local Verification

Run the standalone unit test suite directly via Node and `tsx`:

```bash
npm install
node --import tsx/esm test.js
```

## 📡 API Reference

### `POST /scan`
Audits a code snippet for hardcoded secrets.
```json
{
  "code": "const apiKey = 'sk-proj-1234567890abcdef...';"
}
```

### `POST /guard-ai`
Validates user input against prompt injection signatures.
```json
{
  "prompt": "Summarize today's agritech market trends."
}
```

## 📄 License
MIT — Built by Zachary Mwarari (@haks)
