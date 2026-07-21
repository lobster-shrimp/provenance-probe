# Draft: approval request to OpenRouter

> **Purpose.** A ready-to-send email requesting OpenRouter's written approval to
> run automated model-identity benchmarking (and, separately, red-teaming) under
> our own paid account. Their terms permit benchmarking but prohibit "Red
> Teaming of Models" without prior written approval and restrict
> reverse-engineering the Service (see `docs/tos-notes.md`). Getting this in
> writing converts OpenRouter from the plan's highest-risk target into a cleared
> one. Fill in **[BRACKETS]**; have counsel review before sending.

**To:** [OpenRouter legal / support — e.g. support@openrouter.ai, and any legal
contact in their ToS]
**Subject:** Request for written approval — security research: automated model-identity benchmarking

---

Hello OpenRouter team,

I'm **[NAME]**, **[role / affiliation — e.g. independent security researcher /
ENTITY]**. I run an open-source security-research project that verifies **which
model actually serves a given LLM API endpoint** using black-box measurements
(token-count fingerprints, response-header shapes, latency), for the benefit of
compliance and procurement reviewers.

I would like to run this against my **own paid OpenRouter account** and am
writing to request written approval, because I want to stay squarely within your
Terms of Service. Specifically:

**1. Automated benchmarking / model-identity probing (requesting confirmation).**
The core of the work is benchmarking-adjacent: roughly 20–40 ordinary
`/chat/completions` requests per endpoint per day, `max_tokens=1`, reading the
returned `usage.prompt_tokens`, plus a handful of requests to observe response
headers and latency. It stays well under documented rate limits. Your terms
permit benchmarking, and this does not attempt to access your systems, other
customers' data, or your source code — it only measures the served model's
behavior. **Please confirm this usage is acceptable under my account.**

**2. Red-teaming / behavioral probes (requesting explicit approval).**
A separate, optional layer sends politically sensitive matched-prompt pairs to
measure alignment/refusal asymmetry. Your terms prohibit "Red Teaming of Models"
without prior written approval, so I have this layer **disabled by default** and
will not run it against OpenRouter unless you grant written approval. **If you
are open to it, please let me know the conditions.**

**3. Publication.** Findings would be published under a responsible-disclosure
policy: neutral measurements published as collected; any interpreted verdict
about a specific endpoint withheld until I have notified the relevant party and
allowed a 30-day response window, published with a confidence label and a
measured false-positive rate. I'm happy to share the full policy and to
coordinate with you on anything concerning OpenRouter specifically.

What I'm asking for:
- Written confirmation that (1) is acceptable under my paid account; and
- Whether you'll grant approval for (2), and under what conditions.

I'd also welcome a point of contact for coordinated disclosure. Thank you for
building an aggregator that takes model transparency seriously — that's exactly
the property this project tries to make verifiable.

Best regards,
**[NAME]**
**[ENTITY / CONTACT / PGP if applicable]**

---

*After a reply: record the outcome and any conditions in `docs/tos-notes.md`
under the OpenRouter go/no-go, and flip the OpenRouter target's `authorized`/
`public` flags only to the extent the approval (and Gate 1 counsel review)
covers.*
