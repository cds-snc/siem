import pytest

from siem import sf_rds_mysql_audit
from unittest.mock import patch


@patch("siem.sf_rds_mysql_audit.utils")
def test_transform_mysql_object(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "mysql_object": "$FOO$;"}
    result = sf_rds_mysql_audit.transform(data)
    assert result == {
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
            "query": "FOO",
        },
        "mysql_object": "$FOO$;",
    }


@patch("siem.sf_rds_mysql_audit.utils")
@pytest.mark.parametrize(
    "input,expected",
    [
        ("FAILED_CONNECT", ["authentication", "start", "failed"]),
        ("CONNECT", ["authentication", "start", "authorized"]),
        ("DISCONNECT", ["authentication", "end", "disconnected"]),
    ],
)
def test_transform_mysql_operation(
    MockUtils,
    input,
    expected,
):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    category, type, action = expected
    data = {"event": {}, "rds": {}, "mysql_operation": input}
    result = sf_rds_mysql_audit.transform(data)
    assert result == {
        "event": {"category": category, "type": type, "action": action},
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
        "mysql_operation": input,
    }


@patch("siem.sf_rds_mysql_audit.utils")
@pytest.mark.parametrize(
    "input,expected",
    [
        (0, "success"),
        (1, "failure"),
    ],
)
def test_transform_mysql_retcode(
    MockUtils,
    input,
    expected,
):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"event": {}, "rds": {}, "mysql_retcode": input}
    result = sf_rds_mysql_audit.transform(data)
    assert result == {
        "event": {"outcome": expected},
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
        "mysql_retcode": input,
    }
