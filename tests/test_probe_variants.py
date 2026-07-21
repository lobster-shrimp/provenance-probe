"""Probe randomization: seed 0 is canonical, seeds rotate the exact bytes while
preserving each probe's dominant script, deterministically — and a reference
built for a seed still identifies a tokenizer probed at that seed (round-trip)."""
from provenance_probe import probe_variants as pv
from provenance_probe.data.corpus import TOKENIZER_PROBES
from provenance_probe.probes import tokenizer


def test_seed0_is_canonical():
    assert pv.variant_probes(0) == list(TOKENIZER_PROBES)


def test_variant_changes_bytes_but_keeps_ids():
    base = dict(TOKENIZER_PROBES)
    var = dict(pv.variant_probes(7))
    assert set(var) == set(base)                      # same probe IDs
    changed = sum(1 for k in base if var[k] != base[k])
    assert changed == len(base)                       # every probe's bytes differ


def test_variant_is_deterministic():
    assert pv.variant_probes(7) == pv.variant_probes(7)
    assert pv.variant_probes(7) != pv.variant_probes(8)


def test_dominant_script_preserved():
    base = dict(TOKENIZER_PROBES)
    for pid, text in pv.variant_probes(7):
        assert pv._dominant_script(text) == pv._dominant_script(base[pid]), pid


def test_roundtrip_identification_survives_randomization():
    """Build a reference for seed 5 with a real tokenizer (tiktoken cl100k), then
    'probe' the same seed with the same tokenizer — it must still match top."""
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    seed = 5
    ref_vec = {pid: len(enc.encode(text)) for pid, text in pv.variant_probes(seed)}
    reference = {"variant_seed": seed, "models": {
        "OpenAI-cl100k": {"family": "OpenAI", "origin": "US", "vector": ref_vec},
        # a decoy family with deliberately wrong counts
        "Decoy": {"family": "X", "origin": "CN", "vector": {k: v + 5 for k, v in ref_vec.items()}},
    }}
    observed = {"variant_seed": seed, "vector": dict(ref_vec)}
    results = tokenizer.compare(observed, reference)
    assert results[0]["model"] == "OpenAI-cl100k"
    assert results[0]["score"] >= 0.9


def test_roundtrip_wrong_seed_degrades_match():
    """A reference built at seed 5 does NOT cleanly match a probe run at seed 9
    (the whole point: the exact strings differ per seed)."""
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    ref_vec = {pid: len(enc.encode(t)) for pid, t in pv.variant_probes(5)}
    obs_vec = {pid: len(enc.encode(t)) for pid, t in pv.variant_probes(9)}
    reference = {"variant_seed": 5, "models": {
        "OpenAI-cl100k": {"family": "OpenAI", "origin": "US", "vector": ref_vec}}}
    r5 = tokenizer.compare({"vector": ref_vec}, reference)[0]["score"]
    r9 = tokenizer.compare({"vector": obs_vec}, reference)[0]["score"]
    assert r5 > r9   # same-seed match is stronger than cross-seed
