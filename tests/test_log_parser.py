import unittest
from lms_log_analyzer.src import log_parser
from lms_log_analyzer.src.utils import LRUCache

class TestLogParser(unittest.TestCase):
    def test_parse_syslog_line(self):
        line = (
            '<34>Oct 11 22:14:15 host sshd[123]: Failed password for invalid user '
            'root from 1.1.1.1 port 22'
        )
        parsed = log_parser.parse_syslog_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["severity"], "crit")
        self.assertEqual(parsed["facility"], "auth")
        self.assertIn("Failed password", parsed["msg"])

    def test_fast_score(self):
        line = (
            '<34>Oct 11 22:14:15 host sshd[123]: Failed password for invalid user '
            'root from 1.1.1.1 port 22'
        )
        score = log_parser.fast_score(line)
        self.assertAlmostEqual(score, 0.9, places=2)

class TestLRUCache(unittest.TestCase):
    def test_eviction(self):
        cache = LRUCache(2)
        cache.put('a', 1)
        cache.put('b', 2)
        cache.put('c', 3)
        self.assertIsNone(cache.get('a'))
        self.assertEqual(cache.get('b'), 2)
        self.assertEqual(cache.get('c'), 3)

if __name__ == '__main__':
    unittest.main()
