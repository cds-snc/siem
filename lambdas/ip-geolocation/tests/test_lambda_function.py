import os
import pytest

import lambda_function
from unittest.mock import MagicMock, mock_open, patch


@patch("lambda_function.logger")
def test_handler_missing_maxmind_key(MockLogger):
    assert lambda_function.handler("", "") is False
    MockLogger.error.assert_called_once_with("MAXMIND_KEY is missing")


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.logger")
def test_handler_missing_s3_destination(MockLogger):
    assert lambda_function.handler("", "") is False
    MockLogger.error.assert_called_once_with("S3_DESTINATION is missing")


@patch("lambda_function.FILES", [])
@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.S3_DESTINATION", "FOO")
def test_handler_no_files():
    assert lambda_function.handler("", "") is False


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.S3_DESTINATION", "FOO")
@patch("lambda_function.download_file")
@patch("lambda_function.store_file")
def test_handler_bad_download(MockStore, MockDownload):
    MockDownload.return_value = False
    MockStore.return_value = True
    assert lambda_function.handler("", "") is False


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.S3_DESTINATION", "FOO")
@patch("lambda_function.download_file")
@patch("lambda_function.store_file")
def test_handler_bad_store(MockStore, MockDownload):
    MockDownload.return_value = True
    MockStore.return_value = False
    assert lambda_function.handler("", "") is False


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.S3_DESTINATION", "FOO")
@patch("lambda_function.download_file")
@patch("lambda_function.store_file")
def test_handler(MockStore, MockDownload):
    MockDownload.return_value = True
    MockStore.return_value = True
    assert lambda_function.handler("", "") is True


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.S3_DESTINATION", "FOO")
@patch("lambda_function.download_file")
@patch("lambda_function.logger")
def test_handler_log_exception(MockLogger, MockDownload):
    MockDownload.return_value = True
    MockDownload.side_effect = Exception("ERROR: http status 400")
    assert lambda_function.handler("", "") is False
    MockLogger.error.assert_called_once_with("ERROR: http status 400")


@patch("lambda_function.requests")
def test_download_file_failed_request(MockRequest):
    MockRequest.get.return_value.status_code = 400
    with pytest.raises(Exception):
        lambda_function.download_file("foo")


@patch("lambda_function.requests")
@patch("lambda_function.logger")
def test_download_file_test_write(MockLogger, MockRequest):
    with patch("builtins.open", mock_open()) as mock_file:
        MockRequest.get.return_value.status_code = 200
        assert lambda_function.download_file("foo")
        mock_file.assert_called_with("/tmp/foo.tgz", "wb")
        MockLogger.debug.assert_called_once_with("Downloaded foo")


@patch("lambda_function.MAXMIND_KEY", "FOO")
@patch("lambda_function.requests")
@patch("lambda_function.logger")
def test_download_file_test_url(MockLogger, MockRequest):
    with patch("builtins.open", mock_open()) as _mock_file:
        MockRequest.get.return_value.status_code = 200
        assert lambda_function.download_file("foo")
        MockRequest.get.assert_called_once_with(
            "https://download.maxmind.com/app/geoip_download",
            {"edition_id": "foo", "license_key": "FOO", "suffix": "tar.tgz"},
        )
        MockLogger.debug.assert_called_once_with("Downloaded foo")


@patch("lambda_function.S3_DESTINATION", "FOO")
@patch("lambda_function.get_boto3_client")
@patch("lambda_function.logger")
def test_store_file(MockLogger, MockBoto):
    with patch("lambda_function.tarfile.open", mock_open()) as mock_file:
        MockDir = MagicMock()
        MockDir.name = "foo"
        MockFile = MagicMock()
        MockFile.getmembers.return_value = [MockDir]
        mock_file.return_value.__enter__.return_value = MockFile

        assert lambda_function.store_file("bar")
        MockBoto.return_value.upload_file.assert_called_once_with(
            "/tmp/foo/bar.mmdb", "FOO", "GeoLite2/bar.mmdb"
        )
        MockLogger.debug.assert_called_once_with("Stored bar")
