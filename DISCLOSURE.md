# Responsible Disclosure Policy

> **Status: DRAFT — pending legal review.** This document is written to be
> reviewed by counsel before the Provenance Observatory publishes any
> interpreted verdict about a named third party. It is not itself a legal
> defense. See [docs/tos-notes.md](docs/tos-notes.md) for the open legal
> questions counsel must answer before launch.

## What this covers

The Provenance Observatory continuously probes publicly reachable LLM API
endpoints (initially via aggregators) to assess two independent things:

- **Jurisdiction** — is inference executed by a PRC-domiciled operator or on
  PRC soil?
- **Provenance** — are the served model's weights Chinese-origin, wherever
  served?

Probing uses ordinary API calls under the operator's own paid accounts. It
does not attempt to access private systems, exceed documented rate limits, or
extract another customer's data.

## Two-tier publication (the core of this policy)

We separate *measurements* from *accusations*, and disclose before we accuse.

1. **Neutral evidence — published immediately.** Tokenizer probe IDs and
   observed token counts, wire-layer response headers (auth material
   stripped), latency distributions, and the composite `fingerprint_id`.
   These are measurements. They are committed to a public, append-only log
   (git history) as they are collected, in the spirit of Certificate
   Transparency: the record is complete and tamper-evident.

2. **Interpreted verdict — gated by the disclosure window.** The
   jurisdiction and provenance verdict labels (CONFIRMED / LIKELY /
   INDETERMINATE / UNLIKELY / NO EVIDENCE) and their plain-language meaning
   are an *interpretation* of the neutral evidence. When a verdict is adverse
   to a named operator, it is held in a private staging area and is NOT
   published until the disclosure process below has run.

The disclosure window buys the operator time to respond to the
*interpretation*. It does not hide the underlying measurements, which are
already public.

## Disclosure timeline

| Day | Action |
|-----|--------|
| 0 | Adverse interpreted verdict detected. Operator notified in writing at their published security/abuse contact, with the evidence bundle and our reading of it. A private draft advisory is opened. |
| 0–30 | Operator response window. We engage on any factual correction, missing context, or dispute. Corrections that change the verdict update the draft before anything is published. |
| 30 | If unresolved, the interpreted verdict + advisory are promoted to the public feed with a numbered advisory ID. The operator's response (or the fact that none was received) is published alongside it. |
| Any time | An operator may request a re-test, submit context, or dispute a published advisory; see Corrections below. |

Neutral changes that match an operator's own public announcement (e.g. a
documented model version bump) may be published immediately without the
window, because they are not adverse findings.

## What we do NOT claim

Credibility depends on honest limits. Every published verdict carries a
confidence label and is bound by these caveats:

- **Verdicts are probabilistic, not proof.** A CONFIRMED label means the
  evidence strongly supports the reading, not that it is legally established
  fact.
- **Distillation confounds provenance.** A model can carry one family's
  tokenizer and another's training influence; we state which our evidence
  speaks to.
- **Absence of censorship does not clear provenance**, and presence of it
  does not alone prove jurisdiction.
- **Black-box methods degrade under active evasion** (normalized token
  counts, suppressed logprobs, output filtering). Where evasion is plausible
  we say so.
- We publish the **false-positive rate** measured against known-answer and
  negative controls, so readers can weight our verdicts.

## Corrections and retractions

- An operator or any reader may report an error to the security contact below
  with evidence. We respond within 5 business days.
- If a published verdict is shown to be wrong, we **retract it prominently**:
  the advisory is marked RETRACTED with the reason, kept in the log for the
  record (never silently deleted), and the correction is published on the
  same surfaces as the original.
- The neutral evidence log is append-only; corrections are additions, not
  rewrites.

## Good-faith / safe-harbor intent

This project is security and compliance research conducted in good faith. We
probe only public endpoints, under our own accounts, at ordinary usage
levels, and we disclose before we publish adverse interpretations. We ask
operators to treat findings as coordinated disclosure, not as an attack.
(Whether specific operator terms permit this activity is a separate legal
question tracked in [docs/tos-notes.md](docs/tos-notes.md).)

## Contact

- Security / disclosure: **SECURITY_CONTACT_TBD** (set before launch — a
  monitored address owned by the publishing entity, not a personal account).
- PGP key: **PGP_KEY_TBD**.

## Open items before this policy is live

- [ ] Legal review of this policy and the ToS analysis (Gate 1).
- [ ] Publishing entity established; security contact + PGP key provisioned.
- [ ] Per-operator security/abuse contacts collected for the launch targets.
- [ ] Disclosure-window length (30 days here) confirmed with counsel against
      the norms operators expect.
