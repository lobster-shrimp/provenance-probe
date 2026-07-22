# Live fingerprint corpus

Real full-stack `assess` results against production LLM endpoints (own
authorized accounts). Validates the shipped tokenizer reference vectors against
live services and anchors the corpus with real negative (US) and positive (CN)
cases. Dated snapshot — re-run to refresh.

| Provider | Model | Jurisdiction | Provenance | Tokenizer match | Confidence |
|---|---|---|---|---|---|
| `api.openai.com` | gpt-4o-mini | UNLIKELY (0.182) | NO EVIDENCE (0.029) | OpenAI-o200k (US) 1.0 20/20 | high |
| `api.deepseek.com` | deepseek-chat | CONFIRMED (0.971) | CONFIRMED (1.0) | DeepSeek-V3 (CN) 1.0 20/20 | high |
| `api.moonshot.ai` | kimi-k2.6 | CONFIRMED (0.881) | CONFIRMED (0.995) | Moonshot (CN) 1.0 19/19 | high |

## Notes

- **OpenAI** — clean US anchor: tokenizer o200k matched 20/20; provenance NO EVIDENCE.
- **DeepSeek** — CN anchor: tokenizer DeepSeek-V3 20/20, alignment asymmetry 0.771
  (deflects PRC-sensitive topics vs Western controls). Endpoint echoed `deepseek-v4-flash`.
- **Moonshot (Kimi)** — CN: tokenizer Moonshot 19/19 on `kimi-k2.6`. Key is for the
  `.ai` (international) endpoint, not `.cn`; kimi models are reasoning models that
  reject `temperature=0` (handled by the client's temperature-retry).
- Each live tokenizer match confirms the corresponding shipped reference vector is
  accurate against production, not just internally consistent.
