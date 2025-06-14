import json
import unittest
from unittest.mock import MagicMock, patch

from lms_log_analyzer.src import llm_handler
from lms_log_analyzer.src.utils import LRUCache


class DummyPrompt:
    def format(self, **kwargs):
        return "dummy"


class LLMHandlerTest(unittest.TestCase):
    def setUp(self):
        self.orig_chain = llm_handler.LLM_CHAIN
        self.orig_prompt = getattr(llm_handler, "PROMPT", None)
        self.orig_cost = llm_handler.COST_TRACKER.get_hourly_cost
        llm_handler.LLM_CHAIN = MagicMock()
        llm_handler.LLM_CHAIN.batch.return_value = [json.dumps({"is_attack": False})]
        llm_handler.PROMPT = DummyPrompt()
        llm_handler.CACHE = LRUCache(10)

    def tearDown(self):
        llm_handler.LLM_CHAIN = self.orig_chain
        if self.orig_prompt is not None:
            llm_handler.PROMPT = self.orig_prompt
        llm_handler.COST_TRACKER.get_hourly_cost = self.orig_cost

    def test_summarize_examples_format(self):
        examples = [
            {"log": "line1\n", "analysis": {"attack_type": "phish", "reason": "x"}},
            {"log": "line2", "analysis": {"attack_type": "mal", "reason": "y"}},
        ]
        summary = llm_handler._summarize_examples(examples)

        self.assertNotIn("line1", summary)

        self.assertIn("phish", summary)
        self.assertIn("y", summary)

    def test_llm_analyse_caches_and_summarizes(self):
        line = (
            '<34>Oct 11 22:14:15 host sshd[123]: Failed password for invalid user '
            'root from 1.1.1.1 port 22'
        )
        example = {
            "log": line,
            "analysis": {"attack_type": "ssh", "reason": "bad"},
        }
        alerts = [{"alert": {"original_log": line}, "examples": [example]}]

        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result1 = llm_handler.llm_analyse(alerts)

        llm_handler.LLM_CHAIN.batch.assert_called_once()
        sent = llm_handler.LLM_CHAIN.batch.call_args.args[0][0]["examples_summary"]

        self.assertNotIn("Failed password", sent)
        self.assertIn("ssh", sent)
        self.assertIn("bad", sent)

        syslog_json = llm_handler.LLM_CHAIN.batch.call_args.args[0][0]["syslog_json"]
        self.assertIn("sshd", syslog_json)

        llm_handler.LLM_CHAIN.batch.reset_mock()
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f, *a, **k: f(*a, **k)):
            result2 = llm_handler.llm_analyse(alerts)

        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result1, result2)

    def test_llm_analyse_budget_limit(self):
        llm_handler.COST_TRACKER.get_hourly_cost = MagicMock(return_value=llm_handler.config.MAX_HOURLY_COST_USD)

        alerts = [{"alert": {"original_log": "line"}, "examples": []}]
        with patch("lms_log_analyzer.src.llm_handler.retry_with_backoff", side_effect=lambda f,*a,**k: f(*a, **k)):
            result = llm_handler.llm_analyse(alerts)
        llm_handler.LLM_CHAIN.batch.assert_not_called()
        self.assertEqual(result[0]["reason"], "Budget limit reached")

    def test_llm_analyse_disabled(self):
        llm_handler.LLM_CHAIN = None

        alerts = [{"alert": {"original_log": "line"}, "examples": []}]
        result = llm_handler.llm_analyse(alerts)
        self.assertEqual(result, [None])


if __name__ == "__main__":
    unittest.main()
