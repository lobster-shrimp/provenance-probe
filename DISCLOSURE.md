# Publication Policy

> **Status: operative.** This is the Provenance Observatory's publication policy.
> It favors full transparency: the complete work behind every finding is
> published as collected. Accuracy is served by showing the evidence and by the
> safeguards below, not by withholding.

## What this covers

The Provenance Observatory continuously probes publicly reachable LLM API
endpoints to assess two independent things:

- **Jurisdiction** — is inference executed by a PRC-domiciled operator or on
  PRC soil?
- **Provenance** — are the served model's weights Chinese-origin, wherever
  served?

Probing uses ordinary API calls under the operator's own paid accounts. It
does not attempt to access private systems, exceed documented rate limits, or
extract another customer's data.

## Full transparency — publish the complete work

We publish the **whole record**, as collected, so a reader can see exactly how
each verdict was reached and judge its confidence for themselves:

- **Measurements** — tokenizer probe IDs and observed token counts, wire-layer
  response headers (auth material stripped), latency distributions, network /
  jurisdiction resolution, and the composite `fingerprint_id`.
- **Interpretation** — the jurisdiction and provenance verdict labels
  (CONFIRMED / LIKELY / INDETERMINATE / UNLIKELY / NO EVIDENCE), their
  plain-language meaning, and the reference match that drives them.

Both are committed to a public, append-only, cryptographically signed log (git
history + cosign/Rekor) as they are collected, in the spirit of Certificate
Transparency: the record is complete and tamper-evident. A verdict is never
published without the evidence that produced it.

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

Transparency cuts both ways: because we show our work, an error is easy to
point at and we fix it in the open.

- An operator or any reader may report an error to the security contact below
  with evidence. We respond within 5 business days.
- If a published verdict is shown to be wrong, we **retract it prominently**:
  the record is marked RETRACTED with the reason, kept in the log for the
  record (never silently deleted), and the correction is published on the
  same surfaces as the original.
- The evidence log is append-only; corrections are additions, not rewrites.
- An operator may request a re-test or submit context at any time; a re-test
  that changes the verdict is published like any other update.

## Good-faith intent

This project is security and compliance research conducted in good faith. We
probe only public endpoints, under our own accounts, at ordinary usage levels,
and we publish the complete evidence behind every finding. Operator terms are
tracked as risk context in [docs/tos-notes.md](docs/tos-notes.md); that analysis
is retained for transparency, not as a publication gate.

## Contact

- Security / corrections: **SECURITY_CONTACT_TBD** (set before launch — a
  monitored address owned by the publishing entity, not a personal account).
- PGP key: **PGP_KEY_TBD**.
