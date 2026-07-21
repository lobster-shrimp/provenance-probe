# Terms-of-Service Analysis — Observatory Launch Targets

> **Status: DRAFT — not legal advice.** This is a structured research summary
> prepared for counsel. It records what the operators' public terms say (as of
> July 2026), maps our probe activity to those terms, and lists the specific
> questions counsel must answer before the Provenance Observatory probes and
> publishes about these operators by name. Nothing here clears the activity;
> Gate 1 in the design doc is not satisfied until counsel signs off.

## Decision context

Per design decision U1, the first public targets are **OpenRouter** and
**Together AI**, with the **behavioral (red-teaming) layer OFF**. That choice
maximizes coverage but takes on the most ToS risk, so the counsel review below
is the sharpest launch blocker, not a formality.

## Our probe activity, by layer

The observatory runs only these layers on commercial targets (behavioral is
off):

| Layer | What it sends | ToS character |
|-------|---------------|---------------|
| Tokenizer | ~20 short prompts, `max_tokens=1`, reads `usage.prompt_tokens` | Benchmarking-adjacent; ordinary API calls |
| Wire | A few malformed + normal requests; reads response headers, error schema, `/models` | Benchmarking-adjacent; touches error handling |
| Latency | Repeated small requests; times TTFT / inter-token | Load-adjacent; must stay under documented rate limits |

Behavioral matched-pair probes (politically sensitive prompts) are **red-teaming
content** and are NOT run on OpenRouter or Together. They may run only on
owned/self-hosted controls, or on an operator that grants written approval.

## OpenRouter

Source: OpenRouter Terms of Service, https://openrouter.ai/terms (retrieved
2026-07).

- **Benchmarking:** permitted as a use case; OpenRouter itself exposes
  benchmark data. Our tokenizer/wire/latency layers are benchmarking-adjacent.
- **Red Teaming of Models:** prohibited without OpenRouter's prior written
  approval. → We keep the behavioral layer off. If we ever want it here, we
  need written approval first.
- **Reverse engineering the Service:** prohibited (discovering source code of
  the Service). → Gray area: we reverse-engineer *which model is served*, not
  OpenRouter's software. Counsel must confirm our reading that fingerprinting
  the served model is not "reverse engineering the Service."
- **Rate / load:** honor documented limits; latency layer must be bounded by
  the per-run probe cap (U2).

## Together AI

Source: Together AI Terms of Service, https://www.together.ai/terms-of-service
(retrieved 2026-07).

- **Competitive analysis / benchmarking:** **explicitly prohibited** — the
  terms bar using the service to "engage in competitive analysis or
  benchmarking." → This is the hardest problem. Probing Together and
  publishing provenance findings is squarely within the activity the terms
  name. This is the single item most likely to block a public Together
  verdict.
- **Reverse engineering / vulnerability testing:** prohibited. Same gray-area
  question as OpenRouter re: fingerprinting the served model vs. the service.
- **Excessive load:** prohibited; same rate-limit discipline applies.

## Enforceability context (for counsel, not a conclusion)

Legal scholarship argues AI ToS benchmarking restrictions may be weakly
enforceable or preempted in some contexts (e.g. Stanford Law, "The Mirage of
Artificial Intelligence Terms of Service Restrictions,"
https://law.stanford.edu/publications/the-mirage-of-artificial-intelligence-terms-of-service-restrictions/;
and commentary on AI benchmark clauses). This is context for the discussion,
NOT a basis to proceed. We do not rely on it without counsel.

## Questions counsel must answer before launch

1. **Defamation / trade libel (the load-bearing risk).** If we publish an
   adverse, specific, factual-sounding verdict about a named operator and it
   is wrong, what is our exposure? Does the two-tier model (neutral evidence
   public immediately; interpreted verdict disclosed then published) with
   confidence labels and a published false-positive rate materially reduce it?
2. **Publishing entity.** Should we publish under a formed entity rather than a
   personal maintainer, and in a jurisdiction with anti-SLAPP protection? What
   entity/insurance is appropriate for publishing security findings about named
   companies?
3. **ToS breach consequences.** For OpenRouter (red-teaming/reverse-eng
   clauses) and Together (explicit benchmarking ban): what is the realistic
   consequence of probing under our own paid account — account termination,
   or a viable contract/tort claim? Does publishing the findings change that?
4. **"Reverse engineering the Service" scope.** Does fingerprinting *which
   model is served* (not the operator's software) fall within these clauses?
5. **Together specifically.** Given the explicit benchmarking prohibition, can
   we probe + publish about Together at all without (a) their approval, or (b)
   a determination that the clause is unenforceable for this purpose? If not,
   fallbacks: seek approval, drop Together to controls-only, or publish only
   neutral evidence with no named accusatory verdict.
6. **Disclosure-window length.** Is 30 days (DISCLOSURE.md) appropriate?

## Fallbacks if counsel does not clear a target

- Seek written approval from the operator (required anyway for any behavioral
  probing on OpenRouter).
- Fall back to **controls-only** (self-hosted known-answer + negative control)
  plus any first-party API that explicitly permits evaluation.
- Publish **neutral evidence only** for a target, with no named accusatory
  interpreted verdict, until standing is clear.

## Status

- [ ] Counsel engaged.
- [ ] Q1–Q6 answered in writing.
- [ ] Per-target go / no-go recorded here after the counsel read.
