"""The Ask tab says the true reason when there is no model answer."""

from secagents import qa
from secagents.llm import LLMResult


class Router:
    def __init__(self, providers=("openai",), result=None, errors=(), budget=None):
        self.providers, self.result, self.last_errors, self.budget = list(providers), result, list(errors), budget

    def available_providers(self):
        return self.providers

    def complete(self, *a, **k):
        return self.result

    def complete_json(self, *a, **k):
        return None


def ask_with(monkeypatch, router):
    monkeypatch.setattr(qa, "get_router", lambda: router)
    return qa.ask("What risks are found?", {})["answer"]


def test_a_model_answer_is_returned_as_is(monkeypatch):
    assert ask_with(monkeypatch, Router(result=LLMResult("The risks are X.", "openai", "m"))) == "The risks are X."


def test_no_key_says_no_llm_is_configured(monkeypatch):
    answer = ask_with(monkeypatch, Router(providers=()))
    assert answer.startswith("No LLM is configured") and "most relevant knowledge" in answer


def test_a_key_whose_call_failed_says_so_and_shows_the_providers_reason(monkeypatch):
    answer = ask_with(monkeypatch, Router(errors=["openai (gpt-4.1-mini): 401 invalid_api_key"]))
    assert answer.startswith("A language model is configured, but the call failed")
    assert "No LLM is configured" not in answer and "401 invalid_api_key" in answer and "What the providers said" in answer


def test_a_used_up_allowance_is_explained(monkeypatch):
    class Budget:
        def blocked(self):
            return "Your daily allowance on the shared key is used up."

    answer = ask_with(monkeypatch, Router(providers=(), budget=Budget()))
    assert answer.startswith("Your daily allowance on the shared key is used up. Here is the most relevant knowledge")
