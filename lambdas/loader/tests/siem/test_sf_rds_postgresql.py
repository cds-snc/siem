from siem import sf_rds_postgresql
from unittest.mock import patch


def test_extract_slow_log_no_match():
    data = {"postgresql": {"message": ""}}
    result = sf_rds_postgresql.extract_slow_log(data)
    assert result == {"postgresql": {"message": ""}}


def test_extract_slow_log_statement_match():
    data = {"postgresql": {"message": "statement: SELECT * FORM ALL;"}, "rds": {}}
    result = sf_rds_postgresql.extract_slow_log(data)
    assert result == {
        "postgresql": {
            "message": "statement: SELECT * FORM ALL;",
            "query_step": "execute",
        },
        "rds": {"query": "SELECT * FORM ALL"},
    }


def test_extract_slow_log_duration_match_with_step():
    data = {
        "postgresql": {"message": "duration: 0.117 ms  bind <unnamed>: SELECT 1"},
        "rds": {},
    }
    result = sf_rds_postgresql.extract_slow_log(data)
    assert result == {
        "postgresql": {
            "duration_ms": 0.117,
            "message": "duration: 0.117 ms  bind <unnamed>: SELECT 1",
            "query_step": "bind",
        },
        "rds": {
            "query": "SELECT 1",
            "query_time": 0.00011700000000000001,
        },
    }


def test_extract_slow_log_duration_match_without_step():
    data = {
        "postgresql": {"message": "duration: 0.026 ms"},
        "rds": {},
    }
    result = sf_rds_postgresql.extract_slow_log(data)
    assert result == {
        "postgresql": {
            "duration_ms": 0.026,
            "message": "duration: 0.026 ms",
            "query_step": "execute",
        },
        "rds": {"query_time": 2.6e-05},
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_no_loglevel(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {"rds": {}, "postgresql": {"message": ""}}
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "postgresql": {"message": ""},
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_statement_loglevel(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "rds": {},
        "postgresql": {"log_level": "STATEMENT", "message": "SELECT * FROM ALL;"},
    }
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "postgresql": {"log_level": "STATEMENT", "message": "SELECT * FROM ALL;"},
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
            "query": "SELECT * FROM ALL;",
        },
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_fatal_loglevel(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "rds": {},
        "postgresql": {"log_level": "FATAL", "message": "authentication failed"},
    }
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "event": {
            "action": "failed",
            "category": "authentication",
            "outcome": "failure",
            "type": "start",
        },
        "postgresql": {"log_level": "FATAL", "message": "authentication failed"},
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_log_loglevel_auth_success(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "rds": {},
        "postgresql": {"log_level": "LOG", "message": "connection authorized"},
    }
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "event": {
            "action": "authorized",
            "category": "authentication",
            "outcome": "success",
            "type": "start",
        },
        "postgresql": {"log_level": "LOG", "message": "connection authorized"},
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_log_session_time(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "rds": {},
        "postgresql": {
            "log_level": "LOG",
            "message": "disconnection: session time: 12:34:56",
        },
    }
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "event": {},
        "postgresql": {
            "log_level": "LOG",
            "message": "disconnection: session time: 12:34:56",
            "session_time_seconds": 19376.0,
        },
        "rds": {"cluster_identifier": "Foo", "instance_identifier": "Bar"},
    }


@patch("siem.sf_rds_postgresql.utils")
def test_transform_log_slow_query(MockUtils):
    MockUtils.cluster_instance_identifier.return_value = {
        "cluster": "Foo",
        "instance": "Bar",
    }
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "event": {},
        "rds": {},
        "postgresql": {
            "log_level": "LOG",
            "message": "duration: 0.026 ms",
        },
    }
    result = sf_rds_postgresql.transform(data)
    assert result == {
        "event": {},
        "postgresql": {
            "duration_ms": 0.026,
            "log_level": "LOG",
            "message": "duration: 0.026 ms",
            "query_step": "execute",
        },
        "rds": {
            "cluster_identifier": "Foo",
            "instance_identifier": "Bar",
            "query_time": 2.6e-05,
        },
    }
