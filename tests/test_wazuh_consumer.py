import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from lms_log_analyzer.src import wazuh_consumer
from lms_log_analyzer import config


class TestWazuhConsumer(unittest.TestCase):
    def setUp(self):
        self.orig_file = config.WAZUH_ALERTS_FILE
        self.orig_url = config.WAZUH_ALERTS_URL
        wazuh_consumer._FILE_OFFSET = 0

    def tearDown(self):
        config.WAZUH_ALERTS_FILE = self.orig_file
        config.WAZUH_ALERTS_URL = self.orig_url
        wazuh_consumer._FILE_OFFSET = 0

    def test_read_from_file_and_match(self):
        with tempfile.NamedTemporaryFile('w+', delete=False) as f:
            alert = {"original_log": "line1", "foo": "bar"}
            f.write(json.dumps(alert) + "\n")
            f.flush()
            config.WAZUH_ALERTS_FILE = f.name
            config.WAZUH_ALERTS_URL = None
            result = wazuh_consumer.get_alerts_for_lines(["line1"])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["alert"], alert)

    @patch("lms_log_analyzer.src.wazuh_consumer.requests.get")
    def test_read_from_http(self, mock_get):
        mock_resp = Mock()
        mock_resp.json.return_value = [{"original_log": "line2", "id": 1}]
        mock_resp.raise_for_status = Mock()
        mock_get.return_value = mock_resp
        config.WAZUH_ALERTS_FILE = None
        config.WAZUH_ALERTS_URL = "http://example"
        result = wazuh_consumer.get_alerts_for_lines(["line2"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["alert"], {"original_log": "line2", "id": 1})

