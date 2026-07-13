# Aegis Shield Threat Model

What this gateway defends against, what it explicitly does not, and where each control lives. Written so a security reviewer can disagree with specifics instead of guessing at scope.

## System context

```
[Client app] ──► [Aegis Shield] ──► [LLM provider]
                   │  inbound scanners (PII, injection)
                   │  rate limiter (token bucket / API key hash)
                   │  cache (SQLite, exact match)
                   │  outbound scanners (secrets, infra, refusal bypass)
                   ▼
                 audit log (SQLite) ──► Streamlit dashboard
```

Trust boundaries: the client is **untrusted** (may be compromised or malicious), the provider response is **untrusted** (may echo attacker content or leak), the gateway host is **trusted**.

## Threats addressed

| # | Threat | Vector | Control | Where |
|---|--------|--------|---------|-------|
| T1 | PII exfiltration to third-party provider | User/app includes emails, phones, SSNs, cards in prompts | Inbound regex + Luhn validation; request blocked before egress | `scanners/pii.py` |
| T2 | Prompt injection | "Ignore previous instructions...", overrides, extraction | Keyword rules (10 patterns, severity-ranked) | `scanners/injection.py` L1 |
| T3 | Role smuggling | Fake `[SYSTEM]` / ChatML / `### System:` tags in user content | Structural parsing | `scanners/injection.py` L2 |
| T4 | Obfuscated payloads | Base64/hex-encoded instructions | Shannon entropy > 5.2 bits/char on inputs > 100 chars | `scanners/injection.py` L3 |
| T5 | Secret leakage in responses | Provider echoes API keys (OpenAI/Google/GitHub/AWS shapes) | Outbound scan, response blocked | `scanners/output.py` |
| T6 | Infrastructure disclosure | Private IPs, internal/staging/admin URLs in responses | Outbound scan | `scanners/output.py` |
| T7 | Successful jailbreak reaching users | Model output acknowledging "DAN/jailbroken/developer mode" | Outbound refusal-bypass tripwire | `scanners/output.py` |
| T8 | Bill-spike / DoS via request flooding | Per-key request flood | In-memory token bucket per API-key hash | `limiter.py` |
| T9 | Repeated-question token burn | Identical prompts re-billed | Exact-match SQLite cache (<10 ms hits) | `cache.py` |

Design property worth stating: **inbound blocks cost zero upstream tokens** — the request is rejected before any provider call, so an attacker probing the filter runs up your CPU, not your OpenAI invoice.

## Threats explicitly out of scope (current version)

Honesty section. Each of these is a real gap with a known mitigation path:

- **Novel/paraphrased injections.** The keyword layer catches known phrasings. "Kindly set aside the guidance you received earlier" sails through. *Mitigation path:* a fine-tuned classifier (Llama Guard, DistilBERT on injection corpora) as layer 4 — the scanner interface already supports adding it.
- **Multilingual attacks.** All patterns are English. The same override in Swahili or French is invisible to L1 (L2/L3 still apply).
- **Multi-turn attacks.** Each request is scanned independently; an attack assembled across several innocent-looking turns isn't correlated.
- **Semantic PII.** "My social is oh-seven-eight, oh-five, eleven-twenty" defeats regex. NER-based detection (e.g. Presidio) is the standard upgrade.
- **Homoglyph/unicode evasion.** `Іgnore` with a Cyrillic І bypasses keyword rules. A normalization pass would close most of this cheaply.
- **Streaming responses.** Output scanning assumes a complete response body; SSE streams are not incrementally scanned.
- **Model-specific exploits** (tokenizer quirks, logit manipulation) and **side channels** (timing, length) — out of scope for a proxy by nature.
- **The cache is exact-match only** — it will never serve a *wrong* answer, but paraphrases miss. Semantic caching would trade that guarantee for hit rate.

## Failure posture

- Scanner verdicts are **fail-closed**: a finding at or above the blocking threshold rejects the request/response.
- Upstream/network errors are surfaced to the client as errors, never silently retried with the same payload.
- Every decision (allow, block, category, request id) is written to the audit store — the dashboard reads the same records the blocking path writes, so what you see is what happened.

## Residual-risk summary for a deploying team

Aegis Shield raises the cost of the *common* attacks (copy-pasted jailbreaks, accidental PII, key leakage) from "free" to "requires deliberate evasion effort," and gives you an audit trail when evasion happens. It does not make an unsafe model safe, and a motivated attacker who studies the patterns will find the gaps listed above — that list is your roadmap for hardening, in priority order: unicode normalization, then a classifier layer, then streaming scan support.
