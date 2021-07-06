import pytest
from siem import sf_vpcflowlogs


@pytest.mark.parametrize(
    "input,expected", [("ACCEPT", "success"), ("REJECT", "failure"), ("foo", "unknown")]
)
def test_transform_outcome(input, expected):
    data = {"event": {"action": input}, "network": {"type": "FOO"}, "protocol": "6"}
    result = sf_vpcflowlogs.transform(data)
    assert result == {
        "event": {"action": input, "outcome": expected},
        "network": {"transport": "tcp", "type": "foo"},
        "protocol": "6",
    }


@pytest.mark.parametrize(
    "input,expected",
    [
        ("6", "tcp"),
        ("17", "udp"),
        ("1", "icmp"),
        ("41", "ipv6"),
        ("8", "egp"),
        ("33", "dccp"),
        ("42", "sdrp"),
        ("47", "gre"),
        ("132", "sctp"),
    ],
)
def test_transform_protocol(input, expected):
    data = {
        "event": {"action": "ACCEPT"},
        "network": {"type": "FOO"},
        "protocol": input,
    }
    result = sf_vpcflowlogs.transform(data)
    assert result == {
        "event": {"action": "ACCEPT", "outcome": "success"},
        "network": {"transport": expected, "type": "foo"},
        "protocol": input,
    }


def test_transform_network_type():
    data = {"event": {"action": "ACCEPT"}, "network": {}, "protocol": "6"}
    result = sf_vpcflowlogs.transform(data)
    assert result == {
        "event": {"action": "ACCEPT", "outcome": "success"},
        "network": {"transport": "tcp"},
        "protocol": "6",
    }
