from siem import sf_rds_mysql_slowquery
from unittest.mock import patch


@patch("siem.sf_rds_mysql_slowquery.utils")
def test_transform_mysql_query_time(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "mysql_query": "", "mysql_query_time": 1000}
    result = sf_rds_mysql_slowquery.transform(data)
    assert result == {
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
            "query": "",
            "query_time": 1000,
        },
        "mysql_query": "",
        "mysql_query_time": 1000,
    }


@patch("siem.sf_rds_mysql_slowquery.utils")
def test_transform_mysql_database(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "mysql_query": "use foo;", "mysql_query_time": 1000}
    result = sf_rds_mysql_slowquery.transform(data)
    assert result == {
        "rds": {
            "cluster_identifier": "Foo",
            "database_name": "foo",
            "instance_identifier": "Bar",
            "query_time": 1000,
        },
        "mysql_query": "use foo;",
        "mysql_query_time": 1000,
    }


@patch("siem.sf_rds_mysql_slowquery.utils")
def test_transform_mysql_query(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "mysql_query": "SELECT * FROM *;", "mysql_query_time": 1000}
    result = sf_rds_mysql_slowquery.transform(data)
    assert result == {
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
            "query": "SELECT * FROM *",
            "query_time": 1000,
        },
        "mysql_query": "SELECT * FROM *;",
        "mysql_query_time": 1000,
    }
