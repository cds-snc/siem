from siem import sf_linux_secure
from unittest.mock import patch


@patch("siem.sf_linux_secure.extract_instance_id")
def test_transform_no_match(MockExtractInstanceId):
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": ""}
    result = sf_linux_secure.transform(data)
    assert result == {"syslog_message": ""}


@patch("siem.sf_linux_secure.extract_instance_id")
@patch("siem.sf_linux_secure.extract_from_sshd")
def test_transform_sshd_match(MockExtractfromSSHD, MockExtractInstanceId):
    MockExtractfromSSHD.return_value = {}
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": "", "proc": "sshd"}
    result = sf_linux_secure.transform(data)
    assert MockExtractfromSSHD.called
    assert result == {"proc": "sshd", "syslog_message": ""}


@patch("siem.sf_linux_secure.extract_instance_id")
@patch("siem.sf_linux_secure.extract_from_sudo")
def test_transform_sudo_match(MockExtractfromSudo, MockExtractInstanceId):
    MockExtractfromSudo.return_value = {}
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": "", "proc": "sudo"}
    result = sf_linux_secure.transform(data)
    assert MockExtractfromSudo.called
    assert result == {"proc": "sudo", "syslog_message": ""}
