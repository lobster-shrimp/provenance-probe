"""Tokenizer-unusable attribution: a config/endpoint HTTP error (e.g. a 404 for a
renamed model id) must NOT be mislabeled as a usage-suppression transparency finding.
Regression for the gemini-2.0-flash (renamed to gemini-2.5-flash) 404 case."""

from provenance_probe.assess import tokenizer_unusable_note


def _is_config_error(msg: str) -> bool:
    return ("configuration issue" in msg and "NOT a" in msg
            and "not found" in msg and "transparency finding" not in msg)


def _is_transparency_finding(msg: str) -> bool:
    return "transparency finding" in msg and "HTTP" not in msg


def test_404_is_a_config_error_not_a_transparency_finding():
    msg = tokenizer_unusable_note(
        {"p1": "no usage field (HTTP 404)", "p2": "no usage field (HTTP 404)"},
        "gemini-2.0-flash")
    assert _is_config_error(msg)
    assert "gemini-2.0-flash" in msg  # actionable: names the bad model


def test_other_4xx_and_5xx_are_config_errors():
    for status in ("400", "401", "403", "429", "500", "502", "503"):
        msg = tokenizer_unusable_note({"p": f"no usage field (HTTP {status})"}, "m")
        assert _is_config_error(msg), f"HTTP {status} should be a config error"


def test_200_without_usage_is_the_transparency_finding():
    msg = tokenizer_unusable_note({"p": "no usage field (HTTP 200)"}, "gpt-4o-mini")
    assert _is_transparency_finding(msg)


def test_no_errors_defaults_to_transparency_finding():
    assert _is_transparency_finding(tokenizer_unusable_note(None, "x"))
    assert _is_transparency_finding(tokenizer_unusable_note({}, "x"))


def test_mixed_200_and_404_prefers_the_http_error_signal():
    # If any probe hit a hard HTTP error, surface the actionable config message.
    msg = tokenizer_unusable_note(
        {"p1": "no usage field (HTTP 200)", "p2": "no usage field (HTTP 404)"}, "m")
    assert _is_config_error(msg)


def test_transport_error_without_status_stays_transparency():
    # A bare transport error (no HTTP status) is not a 4xx/5xx -> not misclassified.
    msg = tokenizer_unusable_note({"p": "connection reset by peer"}, "m")
    assert _is_transparency_finding(msg)
