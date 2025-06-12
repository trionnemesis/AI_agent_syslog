import unittest
from lms_log_analyzer.src.vector_db import embed
from lms_log_analyzer.src import log_parser

class TestVectorDB(unittest.TestCase):
    def test_embed_uses_message(self):
        line = '<34>Oct 11 22:14:15 host sshd[123]: Failed password for root'
        vec_full = embed(line)
        parsed = log_parser.parse_syslog_line(line)
        vec_msg = embed(f"{parsed['app']} {parsed['msg']}")
        self.assertEqual(vec_full, vec_msg)

if __name__ == '__main__':
    unittest.main()
