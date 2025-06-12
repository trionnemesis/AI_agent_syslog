import unittest
from unittest.mock import patch, Mock

from lms_log_analyzer.src import wazuh_api
from lms_log_analyzer import config

class TestWazuhAPI(unittest.TestCase):
    def setUp(self):
        self.orig_enabled = config.WAZUH_ENABLED
        self.orig_url = config.WAZUH_API_URL
        self.orig_user = config.WAZUH_API_USER
        self.orig_pw = config.WAZUH_API_PASSWORD
        config.WAZUH_API_URL = "http://wazuh"
        config.WAZUH_API_USER = "user"
        config.WAZUH_API_PASSWORD = "pass"
        config.WAZUH_ENABLED = True
        wazuh_api._TOKEN = None

    def tearDown(self):
        config.WAZUH_ENABLED = self.orig_enabled
        config.WAZUH_API_URL = self.orig_url
        config.WAZUH_API_USER = self.orig_user
        config.WAZUH_API_PASSWORD = self.orig_pw
        wazuh_api._TOKEN = None

    @patch("lms_log_analyzer.src.wazuh_api.requests.post")
    @patch("lms_log_analyzer.src.wazuh_api.requests.get")
    def test_auth_retry_and_parse(self, mock_get, mock_post):
        auth1 = Mock(status_code=200)
        auth1.json.return_value = {"data": {"token": "t1"}}
        auth1.raise_for_status = Mock()
        auth2 = Mock(status_code=200)
        auth2.json.return_value = {"data": {"token": "t2"}}
        auth2.raise_for_status = Mock()
        mock_get.side_effect = [auth1, auth2]

        post1 = Mock(status_code=401)
        post1.raise_for_status = Mock()
        post2 = Mock(status_code=200)
        post2.json.return_value = {"data": {"alerts": [{"foo": "bar"}]}}
        post2.raise_for_status = Mock()
        mock_post.side_effect = [post1, post2]

        alert = wazuh_api.get_alert("logline")
        self.assertEqual(alert["foo"], "bar")
        self.assertEqual(alert["original_log"], "logline")
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(mock_post.call_count, 2)

    def test_wazuh_disabled(self):
        config.WAZUH_ENABLED = False
        self.assertEqual(wazuh_api.get_alert("line1"), {"original_log": "line1"})
