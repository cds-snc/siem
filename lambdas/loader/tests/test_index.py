import logging
import pytest
import re
import time


import boto3
import siem
from siem import geodb, utils

from aws_lambda_powertools.metrics import MetricUnit

from unittest.mock import ANY, call, MagicMock, patch, PropertyMock

with patch("siem.utils") as MockUtils:
    with patch("siem.geodb") as MockGeoDb:
        with patch("boto3.client") as MockBoto:

            etl_config = MagicMock()
            etl_config.__getitem__.side_effect = Exception("Boom!")
            etl_config.getboolean.return_value = "bar"
            etl_config.getint.return_value = "bar"

            MockUtils.get_etl_config.return_value = {
                "Bool": etl_config,
                "Int": etl_config,
                "None": {"foo": "bar"},
                "Raise": etl_config,
                "Re": {"foo": "[a-z]"},
                "ReBad": {"foo": "[a-z"},
                "type_re": ["s3_key_ignored", "log_pattern", "multiline_firstline"],
                "type_int": [
                    "max_log_count",
                    "text_header_line_number",
                    "ignore_header_line_number",
                ],
                "type_bool": [
                    "via_cwl",
                    "via_firelens",
                    "ignore_container_stderr",
                    "timestamp_nano",
                ],
                "type_none": ["foo"],
            }
            import index


def test_extract_logfile_from_s3_with_no_key_raises():
    with pytest.raises(Exception):
        index.extract_logfile_from_s3({})


@patch("index.create_logconfig")
@patch("index.siem")
@patch("index.utils")
def test_extract_logfile_from_s3(MockUtils, MockSiem, MockCreate):
    data = {"s3": {"object": {"key": "s3_key"}}}
    MockSiem.LogS3.return_value = "logfile"
    MockCreate.return_value = "type"
    MockUtils.get_logtype_from_s3key.return_value = "logtype"
    assert index.extract_logfile_from_s3(data) == "logfile"


def test_get_value_from_etl_config_none_type():
    assert index.get_value_from_etl_config("None", "foo", None) == "bar"


def test_get_value_from_etl_config_bool_type():
    assert index.get_value_from_etl_config("Bool", "foo", "bool") == "bar"


def test_get_value_from_etl_config_int_type():
    assert index.get_value_from_etl_config("Int", "foo", "int") == "bar"


def test_get_value_from_etl_config_re_type():
    assert index.get_value_from_etl_config("Re", "foo", "re") == re.compile("[a-z]")


def test_get_value_from_etl_config_unknown_type():
    assert index.get_value_from_etl_config("unknown", "foo", "unknown") == ""


def test_get_value_from_etl_config_key_exception():
    with pytest.raises(KeyError):
        assert index.get_value_from_etl_config("unknown", "bar", None) == ""


def test_get_value_from_etl_config_re_exception():
    with pytest.raises(Exception):
        assert index.get_value_from_etl_config("ReBad", "foo", "re")


def test_get_value_from_etl_config_unknown_exception():
    with pytest.raises(Exception):
        assert index.get_value_from_etl_config("Raise", "foo", None)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("unknown", {}),
        ("nodata", {}),
        (
            "type_re",
            {"log_pattern": "re", "multiline_firstline": "re", "s3_key_ignored": "re"},
        ),
        (
            "type_int",
            {
                "ignore_header_line_number": "int",
                "max_log_count": "int",
                "text_header_line_number": "int",
            },
        ),
        (
            "type_bool",
            {
                "via_cwl": "bool",
                "via_firelens": "bool",
                "ignore_container_stderr": "bool",
                "timestamp_nano": "bool",
            },
        ),
        ("type_none", {"foo": None}),
    ],
)
@patch("index.get_value_from_etl_config")
def test_create_logconfig(MockGetValue, value, expected):
    MockGetValue.side_effect = lambda _x, _y, z=None: z
    assert index.create_logconfig(value) == expected


@patch("index.create_logconfig")
@patch("index.utils.load_sf_module")
@patch("index.siem.LogParser")
def test_get_es_entries(MockLogParser, MockLoadSFModule, MockCreateLogfile):
    logfile = MagicMock()
    logfile.__iter__.return_value = ["foo", "bar"]
    patterns = []
    logparser = MagicMock(
        doc_id="doc_id",
        indexname="indexname",
        json="json",
        ignored_reason="Foo is ignored",
    )
    logparser.is_ignored.__bool__.side_effect = [True, False]
    MockLogParser.return_value = logparser
    a = [x for x in index.get_es_entries(logfile, patterns)]
    assert a == [{"index": {"_id": "doc_id", "_index": "indexname"}}, "json"]
    MockCreateLogfile.assert_called_once_with(logfile.logtype)


@pytest.mark.parametrize(
    "results,expected",
    [
        ({"errors": None, "items": [1, 2], "took": 100}, (100, 2, 0, [])),
        ({"errors": [], "items": [1, 2], "took": 100}, (100, 2, 0, [])),
        (
            {
                "errors": [1],
                "items": [
                    {"index": {"status": 200}},
                    {"index": {"status": 300, "error": "foo"}},
                ],
                "took": 100,
            },
            (100, 1, 1, ["foo"]),
        ),
    ],
)
def test_check_es_results(results, expected):
    assert index.check_es_results(results) == expected


def test_bulkloads_into_elasticsearch_empty():
    es_entries = []
    collected_metrics = {}
    result = index.bulkloads_into_elasticsearch(es_entries, collected_metrics)
    assert result == (
        {
            "total_output_size": 0,
            "total_log_load_count": 0,
            "success_count": 0,
            "error_count": 0,
            "es_response_time": 0,
        },
        [],
    )


@patch("index.check_es_results")
def test_bulkloads_into_elasticsearch_lte_6000000(MockCheckESResults):
    MockCheckESResults.return_value = (100, 1, 0, [])
    es_entries = ["a" * 6000000]
    collected_metrics = {}
    result = index.bulkloads_into_elasticsearch(es_entries, collected_metrics)
    assert result == (
        {
            "total_output_size": 6000000,
            "total_log_load_count": 1,
            "success_count": 1,
            "error_count": 0,
            "es_response_time": 100,
        },
        [],
    )


@patch("index.check_es_results")
def test_bulkloads_into_elasticsearch_lte_6000000_with_error(MockCheckESResults):
    MockCheckESResults.return_value = (100, 1, 1, ["foo"])
    es_entries = ["a" * 6000000, "b" * 6000000]
    collected_metrics = {}
    result = index.bulkloads_into_elasticsearch(es_entries, collected_metrics)
    assert result == (
        {
            "total_output_size": 12000000,
            "total_log_load_count": 2,
            "success_count": 1,
            "error_count": 1,
            "es_response_time": 100,
        },
        [["foo"]],
    )


@patch("index.check_es_results")
def test_bulkloads_into_elasticsearch_greater_than_6000000(MockCheckESResults):
    MockCheckESResults.return_value = (100, 1, 0, [])
    es_entries = ["a" * (6000000 + 1)]
    collected_metrics = {}
    result = index.bulkloads_into_elasticsearch(es_entries, collected_metrics)
    assert result == (
        {
            "total_output_size": 6000001,
            "total_log_load_count": 1,
            "success_count": 1,
            "error_count": 0,
            "es_response_time": 100,
        },
        [],
    )


@patch("index.check_es_results")
def test_bulkloads_into_elasticsearch_greater_than_6000000_with_error(
    MockCheckESResults,
):
    MockCheckESResults.return_value = (100, 1, 1, ["foo"])
    es_entries = ["a" * (6000000 + 1), "b" * (6000000 + 1)]
    collected_metrics = {}
    result = index.bulkloads_into_elasticsearch(es_entries, collected_metrics)
    assert result == (
        {
            "total_output_size": 12000002,
            "total_log_load_count": 2,
            "success_count": 2,
            "error_count": 2,
            "es_response_time": 200,
        },
        [["foo"], ["foo"]],
    )


@patch("index.os")
def test_output_metrics_not_in_lambda(MockOs):
    MockOs.environ.get.return_value = False
    assert index.output_metrics({}) == None


@patch("index.os")
def test_output_metrics(MockOs):
    MockOs.environ.get.return_value = True

    metrics = MagicMock()
    record = {"s3": {"object": {"key": "foo", "size": 100}}}
    logfile = MagicMock(logtype="logtype", total_log_count="total_log_count")

    collected_metrics = {
        "total_output_size": 12000002,
        "total_log_load_count": 2,
        "success_count": 2,
        "error_count": 2,
        "es_response_time": 200,
        "start_time": time.perf_counter(),
    }

    index.output_metrics(metrics, record, logfile, collected_metrics)
    metrics.assert_has_calls(
        [
            call.add_dimension(name="logtype", value="logtype"),
            call.add_metric(name="InputLogFileSize", unit=MetricUnit.Bytes, value=100),
            call.add_metric(
                name="OutputDataSize", unit=MetricUnit.Bytes, value=12000002
            ),
            call.add_metric(name="SuccessLogLoadCount", unit=MetricUnit.Count, value=2),
            call.add_metric(name="ErrorLogLoadCount", unit=MetricUnit.Count, value=2),
            call.add_metric(
                name="TotalDurationTime", unit=MetricUnit.Milliseconds, value=10
            ),
            call.add_metric(
                name="EsResponseTime", unit=MetricUnit.Milliseconds, value=200
            ),
            call.add_metric(name="TotalLogFileCount", unit=MetricUnit.Count, value=1),
            call.add_metric(
                name="TotalLogCount", unit=MetricUnit.Count, value="total_log_count"
            ),
            call.add_metadata(key="s3_key", value="foo"),
        ]
    )


@patch("index.os")
def test_observability_decorator_switcher_in_local(MockOs):
    MockOs.environ.get.return_value = False
    func = lambda x: x
    result = index.observability_decorator_switcher(func)
    assert result.__wrapped__ == func
    assert callable(result)


@patch("index.os")
def test_observability_decorator_switcher_in_lambda(MockOs):
    MockOs.environ.get.return_value = True
    func = lambda x: x
    result = index.observability_decorator_switcher(func)
    assert result.__wrapped__ != func
    assert callable(result)


def test_lambda_handler_no_records():
    assert index.lambda_handler({"Records": []}, {}) == None


@patch("index.extract_logfile_from_s3")
def test_lambda_handler_ignored_records(MockExtract, caplog):
    logfile = MagicMock(is_ignored=True)
    with caplog.at_level(logging.WARNING):
        MockExtract.return_value = logfile
    records = {"Records": ["foo"]}
    assert index.lambda_handler({"Records": records}, {}) == None
    assert "Skipped S3 object because" in caplog.text


@patch("index.extract_logfile_from_s3")
@patch("index.get_es_entries")
@patch("index.bulkloads_into_elasticsearch")
@patch("index.output_metrics")
def test_lambda_handler_ignored_records_on_retry(
    MockOutput, MockBulkload, MockGetESEntries, MockExtract, caplog
):
    logfile = MagicMock()
    logfile.is_ignored.__bool__.side_effect = [False, True]
    MockExtract.return_value = logfile

    MockBulkload.return_value = ({}, [])

    records = {"Records": ["foo"]}
    with caplog.at_level(logging.WARNING):
        assert index.lambda_handler({"Records": records}, {}) == None
    MockGetESEntries.assert_called_once()
    MockBulkload.assert_called_once()
    MockOutput.assert_called_once()
    assert "Skipped S3 object because" in caplog.text


@patch("index.extract_logfile_from_s3")
@patch("index.get_es_entries")
@patch("index.bulkloads_into_elasticsearch")
@patch("index.output_metrics")
def test_lambda_handler_error_count(
    MockOutput, MockBulkload, MockGetESEntries, MockExtract, caplog
):
    logfile = MagicMock(is_ignored=False)
    MockExtract.return_value = logfile

    MockBulkload.return_value = ({"error_count": 1}, ["bar_error"])

    records = {"Records": ["foo"]}
    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception):
            assert index.lambda_handler({"Records": records}, {}) == None
    MockGetESEntries.assert_called_once()
    MockBulkload.assert_called_once()
    MockOutput.assert_called_once()
    assert "bar_error" in caplog.text
    assert "1 of logs were NOT loaded into Amazon ES" in caplog.text


@patch("index.extract_logfile_from_s3")
@patch("index.get_es_entries")
@patch("index.bulkloads_into_elasticsearch")
@patch("index.output_metrics")
def test_lambda_handler_success(
    MockOutput, MockBulkload, MockGetESEntries, MockExtract, caplog
):
    logfile = MagicMock(is_ignored=False)
    MockExtract.return_value = logfile

    MockBulkload.return_value = ({"error_count": 0, "total_log_load_count": 2}, [])

    records = {"Records": ["foo"]}
    with caplog.at_level(logging.INFO):
        assert index.lambda_handler({"Records": records}, {}) == None
    MockGetESEntries.assert_called_once()
    MockBulkload.assert_called_once()
    MockOutput.assert_called_once()
    assert "All logs were loaded into Amazon ES" in caplog.text


@patch("index.extract_logfile_from_s3")
@patch("index.get_es_entries")
@patch("index.bulkloads_into_elasticsearch")
@patch("index.output_metrics")
def test_lambda_handler_no_logs_warning(
    MockOutput, MockBulkload, MockGetESEntries, MockExtract, caplog
):
    logfile = MagicMock(is_ignored=False)
    MockExtract.return_value = logfile

    MockBulkload.return_value = ({"error_count": 0, "total_log_load_count": 0}, [])

    records = {"Records": ["foo"]}
    with caplog.at_level(logging.WARNING):
        assert index.lambda_handler({"Records": records}, {}) == None
    MockGetESEntries.assert_called_once()
    MockBulkload.assert_called_once()
    MockOutput.assert_called_once()
    assert "No entries were successed to load" in caplog.text
