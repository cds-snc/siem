import pytest

from siem import sf_rds_mysql_general
from unittest.mock import patch


@patch("siem.sf_rds_mysql_general.utils")
def test_transform_mysql_object(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "mysql_object": "$FOO$;"}
    result = sf_rds_mysql_general.transform(data)
    assert result == {
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
        },
        "mysql_object": "$FOO$;",
    }
