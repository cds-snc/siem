import pytest
from siem import sf_guardduty


@pytest.mark.parametrize(
    "input,expected",
    [
        (3, "low"),
        (3.9, "low"),
        (5, "medium"),
        (6.9, "medium"),
        (8, "high"),
        (8.9, "high"),
    ],
)
def test_transform_severity_label(input, expected):
    data = {
        "service": {"action": {"actionType": "foo"}},
        "severity": input,
        "type": "Foo:Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "network": {"direction": "INBOUND"},
        "service": {"action": {"actionType": "foo"}},
        "severity": input,
        "severitylabel": expected,
        "type": "Foo:Bar/Baz",
    }


def test_transform_network_connection():
    data = {
        "service": {
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {"connectionDirection": "Foo"},
            }
        },
        "severity": 1,
        "type": "Foo:Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "network": {"direction": "Foo"},
        "service": {
            "action": {
                "actionType": "NETWORK_CONNECTION",
                "networkConnectionAction": {"connectionDirection": "Foo"},
            }
        },
        "severity": 1,
        "severitylabel": "low",
        "type": "Foo:Bar/Baz",
    }


def test_transform_dns_request():
    data = {
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "type": "Foo:Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "network": {"direction": "OUTBOUND"},
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "severitylabel": "low",
        "type": "Foo:Bar/Baz",
    }


def test_transform_outbound_source_switch():
    data = {
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "source": "Foo",
        "type": "Foo:Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "destination": "Foo",
        "network": {"direction": "OUTBOUND"},
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "severitylabel": "low",
        "type": "Foo:Bar/Baz",
    }


def test_transform_outbound_destination_switch():
    data = {
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "destination": "Foo",
        "type": "Foo:Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "network": {"direction": "OUTBOUND"},
        "service": {"action": {"actionType": "DNS_REQUEST"}},
        "severity": 1,
        "severitylabel": "low",
        "source": "Foo",
        "type": "Foo:Bar/Baz",
    }


@pytest.mark.parametrize(
    "input",
    ["Backdoor", "CryptoCurrency", "Trojan"],
)
def test_transform_malware(input):
    data = {
        "event": {},
        "service": {"action": {"actionType": "foo"}},
        "severity": 0,
        "type": input + ":Bar/Baz",
    }
    result = sf_guardduty.transform(data)
    assert result == {
        "ResourceTypeAffected": "Bar",
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": input,
        "event": {"category": "malware"},
        "network": {"direction": "INBOUND"},
        "service": {"action": {"actionType": "foo"}},
        "severity": 0,
        "severitylabel": "low",
        "type": input + ":Bar/Baz",
    }
