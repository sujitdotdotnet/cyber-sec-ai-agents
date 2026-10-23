"""Secrets and personal data are removed before anything is sent to a model or an embedding service."""

from collections import Counter
from dataclasses import replace
from types import SimpleNamespace as NS

import pytest

from secagents.config import settings
from secagents.llm import LLMRouter
from secagents.redact import scrub, scrub_messages, scrub_value

AWS = "AKIAIOSFODNN7EXAMPLE"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SK = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.mark.parametrize("secret,label", [(AWS, "aws-key"), (GH, "github-token"), (SK, "api-key"), (JWT, "jwt"),
                                          ("xoxb-1234567890-abcdefghij", "slack-token"), ("AIza" + "A" * 35, "google-key")])
def test_known_token_formats_are_removed(secret, label):
    clean, found = scrub(f"deploy used {secret} yesterday")
    assert secret not in clean and f"[REDACTED:{label}]" in clean and found[label] == 1 and clean.startswith("deploy used ")


def test_private_keys_are_removed_whole_even_when_cut_off():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----"
    assert scrub(f"key:\n{pem}\nend")[0] == "key:\n[REDACTED:private-key]\nend"
    assert "MIIE" not in scrub("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg")[0]  # truncated block: everything after the header goes


def test_assigned_credentials_keep_the_name_so_the_evidence_still_reads():
    clean, found = scrub('DB_PASSWORD=hunter2hunter2 password: "s3cretValue" api_key = abcd1234 "token": "tok123456" client_secret=zzzzzz')
    assert clean == 'DB_PASSWORD=[REDACTED] password: "[REDACTED]" api_key = [REDACTED] "token": "[REDACTED]" client_secret=[REDACTED]'
    assert found["credential"] == 5


def test_bearer_headers_and_connection_strings():
    clean, found = scrub("Authorization: Bearer abcdefghijklmnop1234567890 and postgresql://app:p%40ss@db.internal:5432/prod")
    assert "abcdefghijklmnop" not in clean and "Bearer [REDACTED]" in clean
    assert clean.endswith("postgresql://app:[REDACTED]@db.internal:5432/prod") and found["url-credential"] == 1


def test_personal_data_emails_cards_and_national_ids():
    clean, found = scrub("contact jane.doe+ops@example.co.uk, card 4111 1111 1111 1111, ssn 123-45-6789")
    assert clean == "contact [REDACTED:email], card [REDACTED:card], ssn [REDACTED:national-id]"
    assert (found["email"], found["card"], found["national-id"]) == (1, 1, 1)


def test_only_real_card_numbers_are_removed():
    assert scrub("order 1234 5678 9012 3456 shipped")[0] == "order 1234 5678 9012 3456 shipped"  # fails the Luhn check
    assert scrub("4111-1111-1111-1111")[0] == "[REDACTED:card]"


def test_ordinary_security_evidence_survives_unchanged():
    line = ("Oct  9 10:08:00 web-01 sshd[4091]: Failed password for invalid user support from 203.0.113.45 port 57096 ssh2\n"
            "198.51.100.7 - - [09/Oct/2026:10:02:11 +0000] \"GET /?q=${jndi:ldap://192.0.2.77:1389/a} HTTP/1.1\" 200 512\n"
            "CVE-2021-44228 T1110.001 sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 on 10.0.0.5:22 at 2026-10-23T05:17:00Z")
    clean, found = scrub(line)
    assert clean == line and not found  # attacker IPs, usernames, CVE ids, hashes, timestamps: all evidence, all kept


def test_nested_values_and_messages_are_scrubbed_without_touching_the_original():
    args = {"text": f"leaked {AWS}", "list": ["mail me@example.com", 5], "n": 3}
    found = Counter()
    out = scrub_value(args, found)
    assert out == {"text": "leaked [REDACTED:aws-key]", "list": ["mail [REDACTED:email]", 5], "n": 3} and args["text"].endswith(AWS)
    history = [{"role": "user", "content": f"key {SK}"},
               {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "name": "analyze_log_text", "arguments": {"text": "password=abcd1234"}}]},
               {"role": "tool", "tool_call_id": "1", "name": "analyze_log_text", "content": "user bob@corp.io"}]
    clean, f2 = scrub_messages(history)
    assert "[REDACTED:api-key]" in clean[0]["content"] and clean[1]["tool_calls"][0]["arguments"]["text"] == "password=[REDACTED]"
    assert clean[2]["content"] == "user [REDACTED:email]" and history[0]["content"].endswith(SK) and sum(f2.values()) == 3


# ---- at the router: the one place every model call passes through ------------------------------------------------------------
class Capture:
    def __init__(self):
        self.sent = []
        reply = NS(choices=[NS(message=NS(content="ok", tool_calls=None))], usage=NS(prompt_tokens=1, completion_tokens=1))
        self.chat = NS(completions=NS(create=lambda **kw: (self.sent.append(kw), reply)[1]))


def router(**kw):
    r = LLMRouter(replace(settings, offline=False, anthropic_api_key="", openai_api_key="k", openrouter_api_key="", **kw))
    stub = Capture()
    r._client = lambda provider: stub
    return r, stub


def test_complete_never_sends_secrets_and_counts_what_it_removed():
    r, stub = router()
    r.complete("You analyse logs for jane@example.com", f"evidence: password=hunter2hunter2 and key {AWS} from 203.0.113.45", agent="t")
    sent = " ".join(m["content"] for m in stub.sent[0]["messages"])
    assert "hunter2" not in sent and AWS not in sent and "jane@example.com" not in sent and "203.0.113.45" in sent
    assert r.redactions["credential"] == 1 and r.redactions["aws-key"] == 1 and r.redactions["email"] == 1 and r.redaction_total == 3


def test_chat_scrubs_history_and_tool_arguments_too():
    r, stub = router()
    r.chat("sys", [{"role": "user", "content": f"my token {GH}"},
                   {"role": "assistant", "content": "", "tool_calls": [{"id": "c", "name": "t", "arguments": {"text": "pw=1 password: abcdefgh"}}]},
                   {"role": "tool", "tool_call_id": "c", "name": "t", "content": "mail a@b.io"}], [])
    payload = repr(stub.sent[0]["messages"])
    assert GH not in payload and "abcdefgh" not in payload and "a@b.io" not in payload
    assert r.redaction_total == 3


def test_the_embedding_query_is_scrubbed_too():
    from secagents.rag.store import KnowledgeBase

    seen = []
    kb = KnowledgeBase(replace(settings, offline=True), persist=False)
    kb.embed = lambda texts: (seen.extend(texts), [[0.0] * 512 for _ in texts])[1]
    kb.search("cves", f"attack with key {AWS} against log4j", k=1)
    assert seen and AWS not in seen[0] and "[REDACTED:aws-key]" in seen[0]


def test_the_guardrail_can_be_switched_off_explicitly():
    r, stub = router(redact_before_model=False)
    r.complete("s", f"key {AWS}")
    assert AWS in stub.sent[0]["messages"][1]["content"] and r.redaction_total == 0


def test_the_default_is_on():
    assert replace(settings).redact_before_model is True


def test_environment_style_names_are_caught_but_plain_numbers_are_not():
    clean, found = scrub("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG max_tokens=4000 token_count=123456 DB_PASSWORD=hunter2hunter2")
    assert clean == "AWS_SECRET_ACCESS_KEY=[REDACTED] max_tokens=4000 token_count=123456 DB_PASSWORD=[REDACTED]"
    assert found["credential"] == 2
    assert scrub("session_token=0123456789012345")[0] == "session_token=[REDACTED]"  # a long digit string after a token name IS kept secret


# ---- speed: this runs on every prompt, so it must stay linear (a slow pattern once froze the Log Monitor) -----------------------
HOSTILE = {
    "long-token": lambda: "a" * 200_000, "dotted": lambda: "abc.def-" * 40_000, "email-like": lambda: "a." * 100_000,
    "many-equals": lambda: "token=" * 40_000, "keyword-then-run": lambda: "password" + "x" * 100_000, "schemes": lambda: "http://" * 20_000,
    "many-ats": lambda: "user@" * 40_000, "digit-groups": lambda: "1234 " * 60_000, "dashes": lambda: "-" * 200_000,
}


@pytest.mark.parametrize("name", list(HOSTILE))
def test_hostile_or_huge_text_is_scrubbed_quickly(name):
    import time

    text = HOSTILE[name]()
    start = time.perf_counter()
    scrub(text)
    assert time.perf_counter() - start < 2.0


def test_a_realistic_large_prompt_is_scrubbed_in_well_under_a_second():
    import json
    import time

    from secagents.graph import run

    state = dict(run())
    text = json.dumps({k: v for k, v in state.items() if k != "report_md"}, default=str, indent=1)
    assert len(text) > 50_000
    start = time.perf_counter()
    scrub(text)
    assert time.perf_counter() - start < 1.0
