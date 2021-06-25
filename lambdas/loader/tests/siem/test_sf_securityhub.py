import pytest
from siem import sf_securityhub
from unittest.mock import patch


def test_get_values_from_asff_resources_instance_key():
    resources = [
        {"Id": "foo/bar", "Type": "AwsEc2Instance"},
        {
            "Id": "foo:null",
            "Details": {
                "AwsIamAccessKey": {"PrincipalId": "foo:bar", "PrincipalName": "baz"}
            },
            "Type": "AwsIamAccessKey",
        },
    ]
    result = sf_securityhub.get_values_from_asff_resources(resources)
    assert result == {
        "cloud": {"instance": {"id": "bar"}},
        "user": {"id": "foo", "name": "baz"},
    }


def test_get_values_from_asff_resources_volume_role():
    resources = [
        {
            "Details": {"AwsEc2Volume": {"Attachments": [{"InstanceId": "bar"}]}},
            "Type": "AwsEc2Volume",
        },
        {"Id": "foo/bar", "Type": "AwsIamRole"},
    ]
    result = sf_securityhub.get_values_from_asff_resources(resources)
    assert result == {"cloud": {"instance": {"id": "bar"}}, "user": {"name": "bar"}}


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_network_connection(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "NETWORK_CONNECTION",
            "aws/guardduty/service/action/networkConnectionAction/connectionDirection": "outbound",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/Foo:Bar/Baz"},
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "intrusion_detection", "module": "guardduty"},
        "network": {"direction": "outbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "NETWORK_CONNECTION",
            "aws/guardduty/service/action/networkConnectionAction/connectionDirection": "outbound",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/Foo:Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_dns_request(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "DNS_REQUEST",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/Foo:Bar/Baz"},
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "intrusion_detection", "module": "guardduty"},
        "network": {"direction": "outbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "DNS_REQUEST",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/Foo:Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_no_match(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/Foo:Bar/Baz"},
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "intrusion_detection", "module": "guardduty"},
        "network": {"direction": "inbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/Foo:Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_network_flip(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "network": {"direction": "outbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/Foo:Bar/Baz"},
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "intrusion_detection", "module": "guardduty"},
        "network": {"direction": "inbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/Foo:Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_outbound_flip(MockAsff):
    MockAsff.return_value = {}
    data = {
        "destination": "Bar",
        "event": {},
        "network": {"direction": "outbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "DNS_REQUEST",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/Foo:Bar/Baz"},
        "source": "Foo",
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "destination": "Foo",
        "event": {"category": "intrusion_detection", "module": "guardduty"},
        "network": {"direction": "outbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "DNS_REQUEST",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/Foo:Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": "Foo",
        "source": "Bar",
    }


@pytest.mark.parametrize(
    "input",
    ["Backdoor", "CryptoCurrency", "Trojan"],
)
@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_guardduty_malware(MockAsff, input):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "rule": {"name": "/" + input + ":Bar/Baz"},
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "malware", "module": "guardduty"},
        "network": {"direction": "inbound"},
        "ProductFields": {
            "aws/guardduty/service/action/actionType": "",
            "aws/securityhub/ProductName": "GuardDuty",
        },
        "Resources": [],
        "ResourceTypeAffected": "Bar",
        "rule": {"name": "/" + input + ":Bar/Baz"},
        "ThreatFamilyName": "Baz",
        "ThreatPurpose": input,
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_iam_access(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {
            "aws/securityhub/ProductName": "IAM Access Analyzer",
        },
        "Resources": [],
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"module": "iam access analyzer"},
        "ProductFields": {
            "aws/securityhub/ProductName": "IAM Access Analyzer",
        },
        "Resources": [],
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_security_hub(MockAsff):
    MockAsff.return_value = {}
    data = {
        "@timestamp": "2021-06-25T14:26:59+00:00",
        "event": {},
        "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
        "Resources": [],
        "rule": {},
        "Title": "Foo",
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "__doc_id_suffix": 1624631219,
        "@timestamp": "2021-06-25T14:26:59+00:00",
        "event": {"module": "security hub"},
        "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
        "Resources": [],
        "rule": {"name": "Foo"},
        "Title": "Foo",
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_inspector(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {"aws/securityhub/ProductName": "Inspector"},
        "Resources": [],
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "package", "module": "inspector"},
        "ProductFields": {"aws/securityhub/ProductName": "Inspector"},
        "Resources": [],
    }


@patch("siem.sf_securityhub.get_values_from_asff_resources")
def test_transform_macie(MockAsff):
    MockAsff.return_value = {}
    data = {
        "event": {},
        "ProductFields": {"aws/securityhub/ProductName": "Macie"},
        "Resources": [],
        "rule": {},
        "Title": "Foo",
    }
    result = sf_securityhub.transform(data)
    assert result == {
        "event": {"category": "intrusion_detection", "module": "macie"},
        "ProductFields": {"aws/securityhub/ProductName": "Macie"},
        "Resources": [],
        "rule": {"name": "Foo"},
        "Title": "Foo",
    }
