from siem import sf_rds_mysql_error
from unittest.mock import patch


@patch("siem.sf_rds_mysql_error.utils")
def test_transform_mysql_instance(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"mysql_message": "", "rds": {}}
    result = sf_rds_mysql_error.transform(data)
    assert result == {
        "mysql_message": "",
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
    }


@patch("siem.sf_rds_mysql_error.utils")
def test_transform_mysql_auth_failed(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "mysql_message": "Access denied for user 'foo'@'127.0.0.1'",
        "rds": {},
    }
    result = sf_rds_mysql_error.transform(data)
    assert result == {
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "failed",
            "outcome": "failure",
        },
        "mysql_host": "127.0.0.1",
        "mysql_message": "Access denied for user 'foo'@'127.0.0.1'",
        "mysql_username": "foo",
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
        "source": {"address": "127.0.0.1", "ip": "127.0.0.1"},
        "user": {"name": "foo"},
    }


@patch("siem.sf_rds_mysql_error.utils")
def test_transform_mysql_unkown_db(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "mysql_message": "Unknown database 'foo'",
        "rds": {},
    }
    result = sf_rds_mysql_error.transform(data)
    assert result == {
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "failed",
            "outcome": "failure",
        },
        "mysql_database": "foo",
        "mysql_message": "Unknown database 'foo'",
        "rds": {
            "cluster_identifier": "Foo",
            "database_name": "foo",
            "instance_identifier": "Bar",
        },
    }
