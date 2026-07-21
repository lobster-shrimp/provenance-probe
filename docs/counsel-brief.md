# Counsel engagement brief — Provenance Observatory

> **Purpose.** A one-page brief to hand to a lawyer so they can scope the legal
> review that gates public launch (Gate 1). Read alongside `DISCLOSURE.md` (our
> responsible-disclosure policy) and `docs/tos-notes.md` (per-provider terms
> analysis + the specific questions). Placeholders in **[BRACKETS]** are for you
> to fill in.

## What we are building

An open-source security-research project that continuously and independently
determines **which AI model actually serves a given public LLM API endpoint**,
and whether it is Chinese-origin or under PRC jurisdiction — using black-box
measurements (token-count fingerprints, response-header shapes, latency). It is
intended to give compliance and procurement reviewers citable evidence about
whether an endpoint serves what its vendor claims, and whether that silently
changes over time.

## What we intend to publish, and how

We separate measurements from accusations and disclose before we accuse:

- **Neutral evidence** (token counts, headers, latency, a fingerprint hash) is
  published immediately as an append-only, cryptographically signed log.
- **Interpreted verdicts** ("this endpoint is serving Chinese-origin weights")
  are *withheld*: the vendor is notified, given a **30-day** response window,
  and the verdict is published only afterward, with a confidence label and a
  published false-positive rate. Verdicts are stated as probabilistic, not fact.
  Full policy: `DISCLOSURE.md`.

## The legal risk we are asking you to assess

Publishing an adverse, specific, factual-sounding statement about a **named
commercial company** ("Vendor X's endpoint serves Chinese-origin weights") is
the classic fact pattern for a **trade-libel / defamation** claim if a verdict
is wrong. Separately, the endpoints we probe are aggregators whose terms of
service restrict some of this activity: **OpenRouter** prohibits "red teaming"
without approval and restricts reverse-engineering; **Together AI** explicitly
prohibits "competitive analysis or benchmarking." Details and sources:
`docs/tos-notes.md`.

## What we need from you (written answers)

The six questions are enumerated in `docs/tos-notes.md`; the load-bearing ones:

1. **Defamation / trade-libel exposure.** Given the two-tier model (neutral
   evidence public immediately; interpreted verdict disclosed then published,
   confidence-labeled, with a published false-positive rate), what is our
   realistic exposure, and what would materially reduce it?
2. **Publishing entity.** Should we publish through a formed entity (which,
   where — anti-SLAPP jurisdiction?) rather than an individual, and what
   insurance is appropriate?
3. **Probe + publish about OpenRouter and Together by name.** Given their
   terms, can we probe these two and publish provenance findings about them?
   If not, what changes that (their written approval; a determination that a
   clause is unenforceable for this purpose)?
4. **"Reverse engineering the Service" scope** — does fingerprinting *which
   model is served* fall within those clauses?
5. **Together's benchmarking prohibition** — specifically, can we probe and
   publish about Together at all, or must we seek approval / fall back?
6. **Disclosure-window length** — is 30 days appropriate?

Deliverable we need: written answers to the above, a recommended publishing
entity/structure, and a **per-target go / no-go** we can record in
`docs/tos-notes.md`.

## Counsel profile

Media / First-Amendment + technology practice (experience with publishing
adverse factual claims about named companies — security-research or journalism
publication defense), plus a commercial-contract read of the aggregator terms.
A general corporate attorney is not the right fit alone.

## Current posture (so nothing ships prematurely)

Until we have your written answers: the two commercial targets are configured
`public: false` and are not probed; only self-hosted controls (our own
endpoints, zero third-party terms implicated) run. Nothing accusatory about a
named vendor is published.

**Attachments:** `DISCLOSURE.md`, `docs/tos-notes.md`.
Contact: **[YOUR NAME / ENTITY / EMAIL]**.
