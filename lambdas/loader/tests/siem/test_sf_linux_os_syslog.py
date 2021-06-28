import pytest

from siem import sf_linux_os_syslog
from unittest.mock import patch


@patch("siem.sf_linux_os_syslog.utils")
def test_extract_instance_id(MockUtils):
    MockUtils.extract_aws_instanceid_from_text.return_value = "Foo"
    data = {"@log_stream": "Foo"}
    result = sf_linux_os_syslog.extract_instance_id(data, {})
    assert result == {"cloud": {"instance": {"id": "Foo"}}}


@patch("siem.sf_linux_os_syslog.utils")
def test_extract_instance_id_no_id(MockUtils):
    MockUtils.extract_aws_instanceid_from_text.return_value = False
    data = {"@log_stream": "Foo"}
    result = sf_linux_os_syslog.extract_instance_id(data, {})
    assert result == {}


def test_extract_from_sshd_no_match():
    data = {"syslog_message": ""}
    result = sf_linux_os_syslog.extract_from_sshd(data, {})
    assert result == {"event": {"module": "secure"}}


@pytest.mark.parametrize(
    "log",
    [
        ("error: AuthorizedKeysCommand A username SHA"),
        ("pam_unixs: session closed for user username"),
        ("pam_unixs: session opened for user username by username("),
    ],
)
def test_extract_from_sshd_user_match(log):
    data = {"event": {}, "syslog_message": log}
    result = sf_linux_os_syslog.extract_from_sshd(data, {})
    assert result["user"]["name"] == "username"


@pytest.mark.parametrize(
    "log,port",
    [
        ("connection from 127.0.0.1 port 80", "80"),
        (" 127.0.0.1 ", ""),
        ("Accepted publickey for username from 127.0.0.1 port 80", "80"),
        ("Disconnected from 127.0.0.1 port 80", "80"),
        ("reverse mapping checking [127.0.0.1]", ""),
        ("Connection reset by 127.0.0.1 port 80", "80"),
    ],
)
def test_extract_from_sshd_source_ip_no_action(log, port):
    data = {"event": {}, "syslog_message": log}
    result = sf_linux_os_syslog.extract_from_sshd(data, {})
    assert result["source"]["port"] == port


@pytest.mark.parametrize(
    "log,outcome",
    [
        ("Accepted publickey", "success"),
        ("Disconnected from 127.0.0.1 port 80", "success"),
        ("pam_unixs: session opened for user username by username(", "success"),
        ("Failed publickey", "failure"),
        ("Invalid user publickey", "failure"),
        ("error: AuthorizedKeysCommand A username SHA", "failure"),
        ("Connection reset by 127.0.0.1 port 80", ""),
        ("Connection closed by 127.0.0.1 port 80", ""),
        ("reverse mapping checking [127.0.0.1]", "unknown"),
    ],
)
def test_extract_from_sshd_action(log, outcome):
    data = {"event": {}, "syslog_message": log}
    result = sf_linux_os_syslog.extract_from_sshd(data, {})
    if outcome != "":
        assert result["event"]["outcome"] == outcome
    else:
        assert "outcome" not in result["event"]


def test_extract_from_sudo_no_match():
    data = {"syslog_message": ""}
    result = sf_linux_os_syslog.extract_from_sudo(data, {})
    assert result == {"event": {"module": "secure"}}


@pytest.mark.parametrize(
    "log",
    [
        ("pam_unixs: session closed for user username"),
        ("pam_unixs: session opened for user username by username("),
    ],
)
def test_extract_from_sudo_user_match(log):
    data = {"syslog_message": log}
    result = sf_linux_os_syslog.extract_from_sudo(data, {})
    assert result["user"]["name"] == "username"


@pytest.mark.parametrize(
    "log,action",
    [("username : COMMAND=foo", "foo"), ("username : COMMAND=bar", "bar")],
)
def test_extract_from_sudo_action_match(log, action):
    data = {"syslog_message": log}
    result = sf_linux_os_syslog.extract_from_sudo(data, {})
    assert result == {
        "event": {"action": action, "outcome": "success"},
        "user": {"name": "username"},
    }


@patch("siem.sf_linux_os_syslog.extract_instance_id")
def test_transform_no_match(MockExtractInstanceId):
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": ""}
    result = sf_linux_os_syslog.transform(data)
    assert result == {"syslog_message": ""}


@patch("siem.sf_linux_os_syslog.extract_instance_id")
@patch("siem.sf_linux_os_syslog.extract_from_sshd")
def test_transform_sshd_match(MockExtractfromSSHD, MockExtractInstanceId):
    MockExtractfromSSHD.return_value = {}
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": "", "proc": "sshd"}
    result = sf_linux_os_syslog.transform(data)
    assert MockExtractfromSSHD.called
    assert result == {'__index_name': 'log-linux-secure', 'proc': 'sshd', 'syslog_message': ''}


@patch("siem.sf_linux_os_syslog.extract_instance_id")
@patch("siem.sf_linux_os_syslog.extract_from_sudo")
def test_transform_sudo_match(MockExtractfromSudo, MockExtractInstanceId):
    MockExtractfromSudo.return_value = {}
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": "", "proc": "sudo"}
    result = sf_linux_os_syslog.transform(data)
    assert MockExtractfromSudo.called
    assert result == {'__index_name': 'log-linux-secure', 'proc': 'sudo', 'syslog_message': ''}


@patch("siem.sf_linux_os_syslog.extract_instance_id")
def test_transform_su_match(MockExtractInstanceId):
    MockExtractInstanceId.return_value = {}
    data = {"syslog_message": "", "proc": "su"}
    result = sf_linux_os_syslog.transform(data)
    assert result == {'__index_name': 'log-linux-secure', 'proc': 'su', 'syslog_message': ''}