import datetime
import logging
import os
import pytest
import re
from siem import utils
from unittest.mock import call, MagicMock, mock_open, patch


@pytest.mark.parametrize(
    "input,expected",
    [
        ("abcd/123456789012/efgh", "123456789012"),
        ("abcd-123456789012-efgh", None),
    ],
)
def test_extract_aws_account_from_text(input, expected):
    assert utils.extract_aws_account_from_text(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        ("abcd/ca-central-1/efgh", "ca-central-1"),
        ("abcd-123456789012-efgh", None),
    ],
)
def test_extract_aws_region_from_text(input, expected):
    assert utils.extract_aws_region_from_text(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        ("abcd/i-1a2b3c4d/efgh", "i-1a2b3c4d"),
        ("abcd/i-1234567890abcdef0/efgh", "i-1234567890abcdef0"),
        ("abcd-123456789012-efgh", None),
    ],
)
def test_extract_aws_instanceid_from_text(input, expected):
    assert utils.extract_aws_instanceid_from_text(input) == expected


@patch("siem.utils.extract_rds_cluster_instance_identifier")
def test_cluster_instance_identifier_with_bad_log_group(MockRdsExtract):
    MockRdsExtract.return_value = None, None
    data = {"@log_stream": ""}
    result = utils.cluster_instance_identifier(data)
    assert result == {"cluster": None, "instance": None}
    assert MockRdsExtract.called_with_arguments(None, None, "")


@patch("siem.utils.extract_rds_cluster_instance_identifier")
def test_cluster_instance_identifier_with_log_group(MockRdsExtract):
    MockRdsExtract.return_value = "Foo", "Bar"
    data = {"@log_group": "a/b/c/d/e", "@log_stream": ""}
    result = utils.cluster_instance_identifier(data)
    assert result == {"cluster": "Foo", "instance": "Bar"}
    assert MockRdsExtract.called_with_arguments("d", "e", "")


def test_extract_rds_cluster_instance_identifier_empty():
    assert utils.extract_rds_cluster_instance_identifier("", "", "") == (None, None)


def test_extract_rds_cluster_instance_identifier_instance():
    assert utils.extract_rds_cluster_instance_identifier(
        "instance", "database-1", ""
    ) == (None, "database-1")


def test_extract_rds_cluster_instance_identifier_cluster():
    assert utils.extract_rds_cluster_instance_identifier(
        "cluster", "database-1", "instance-1.abcd"
    ) == ("database-1", "instance-1")


def test_convert_underscore_field_into_dot_notation_no_prefix():
    assert utils.convert_underscore_field_into_dot_notation(None, {}) == {}


def test_convert_underscore_field_into_dot_notation_prefix_missing_in_log():
    assert utils.convert_underscore_field_into_dot_notation("foo", {}) == {"foo": {}}


def test_convert_underscore_field_into_dot_notation():
    data = {"foo_bar": "baz"}
    result = utils.convert_underscore_field_into_dot_notation("foo", data)
    assert result == {"foo": {"bar": "baz"}}


def test_get_timestr_from_logdata_dict_no_nanotime_parse():
    data = {"log": {"timestamp": "2021-06-29T12:56:58Z"}}
    result = utils.get_timestr_from_logdata_dict(data, "log.timestamp", False)
    assert result == "2021-06-29T12:56:58+00:00"


def test_get_timestr_from_logdata_dict_with_epoch():
    data = {"log": {"timestamp": 1624975451}}
    result = utils.get_timestr_from_logdata_dict(data, "log.timestamp", False)
    assert result == 1624975451


def test_get_timestr_from_logdata_dict_with_nanotime_parse():
    data = {"log": {"timestamp": "2021-06-29T12:56:58.00.00Z"}}
    result = utils.get_timestr_from_logdata_dict(data, "log.timestamp", True)
    assert result == "2021-06-29T12:56:58.00.000+00:00"


@patch("siem.utils.convert_epoch_to_datetime")
@patch("siem.utils.convert_syslog_to_datetime")
@patch("siem.utils.convert_iso8601_to_datetime")
@patch("siem.utils.convert_custom_timeformat_to_datetime")
def test_convert_timestr_to_datetime(MochCustom, MockIso8601, MockSyslog, MockEpoch):
    utils.convert_timestr_to_datetime("1", "2", "epoch", "TZ")
    MockEpoch.assert_called_once_with("1", "TZ")

    utils.convert_timestr_to_datetime("1", "2", "syslog", "TZ")
    MockSyslog.assert_called_once_with("1", "TZ")

    utils.convert_timestr_to_datetime("1", "2", "iso8601", "TZ")
    MockIso8601.assert_called_once_with("1", "TZ", "2")

    utils.convert_timestr_to_datetime("1", "2", "custom", "TZ")
    MochCustom.assert_called_once_with("1", "TZ", "custom", "2")


@pytest.mark.parametrize(
    "time,tz,expected",
    [
        (1000000000001, None, datetime.datetime(2001, 9, 9, 1, 46, 40, 1000)),
        (
            1000000000001,
            datetime.timezone.utc,
            datetime.datetime(
                2001, 9, 9, 1, 46, 40, 1000, tzinfo=datetime.timezone.utc
            ),
        ),
        (1624975451, None, datetime.datetime(2021, 6, 29, 14, 4, 11)),
        (
            1624975451,
            datetime.timezone.utc,
            datetime.datetime(2021, 6, 29, 14, 4, 11, tzinfo=datetime.timezone.utc),
        ),
    ],
)
def test_convert_epoch_to_datetime(time, tz, expected):
    assert utils.convert_epoch_to_datetime(time, tz) == expected


@pytest.mark.parametrize(
    "time,tz,expected",
    [
        (
            "Jan 01 00:00:00",
            datetime.timezone.utc,
            datetime.datetime(
                datetime.datetime.now(datetime.timezone.utc).year,
                1,
                1,
                0,
                0,
                tzinfo=datetime.timezone.utc,
            ),
        ),
        (
            "Jan 01 00:00:00.12",
            datetime.timezone.utc,
            datetime.datetime(
                datetime.datetime.now(datetime.timezone.utc).year,
                1,
                1,
                0,
                0,
                0,
                120000,
                tzinfo=datetime.timezone.utc,
            ),
        ),
        (
            "Dec 31 23:59:59",
            datetime.timezone.utc,
            datetime.datetime(
                datetime.datetime.now(datetime.timezone.utc).year - 1,
                12,
                31,
                23,
                59,
                59,
                tzinfo=datetime.timezone.utc,
            ),
        ),
    ],
)
def test_convert_syslog_to_datetime(time, tz, expected):
    assert utils.convert_syslog_to_datetime(time, tz) == expected


@pytest.mark.parametrize(
    "time,expected",
    [
        (
            "2021-06-29T12:56:58+00:00",
            datetime.datetime(2021, 6, 29, 12, 56, 58, tzinfo=datetime.timezone.utc),
        ),
        (
            "2021-06-29T12:56:58",
            datetime.datetime(2021, 6, 29, 12, 56, 58, tzinfo=datetime.timezone.utc),
        ),
        (
            "2021-06-29T12:56:58+0000",
            datetime.datetime(2021, 6, 29, 12, 56, 58, tzinfo=datetime.timezone.utc),
        ),
    ],
)
def test_convert_iso8601_to_datetime(time, expected):
    assert (
        utils.convert_iso8601_to_datetime(time, datetime.timezone.utc, "foo")
        == expected
    )


def test_convert_iso8601_to_datetime_raise_error():
    with pytest.raises(ValueError):
        utils.convert_iso8601_to_datetime("", datetime.timezone.utc, "foo")


@pytest.mark.parametrize(
    "time,format,expected",
    [
        (
            "29/06/2021 12:56:58",
            "%d/%m/%Y %H:%M:%S",
            datetime.datetime(2021, 6, 29, 12, 56, 58, tzinfo=datetime.timezone.utc),
        ),
        (
            "29/06/2021 12:56:58 UTC",
            "%d/%m/%Y %H:%M:%S %Z",
            datetime.datetime(2021, 6, 29, 12, 56, 58, tzinfo=datetime.timezone.utc),
        ),
    ],
)
def test_convert_custom_timeformat_to_datetime(time, format, expected):
    assert (
        utils.convert_custom_timeformat_to_datetime(
            time, datetime.timezone.utc, format, "foo"
        )
        == expected
    )


def test_convert_custom_timeformat_to_datetime_raise_error():
    with pytest.raises(ValueError):
        utils.convert_custom_timeformat_to_datetime(
            "", datetime.timezone.utc, "%d/%m/%Y %H:%M:%S %Z", "foo"
        )


@patch.dict(os.environ, {"ES_ENDPOINT": "foo"}, clear=True)
def test_get_es_hostname_with_os_var():
    assert utils.get_es_hostname() == "foo"


@patch("siem.utils.configparser")
def test_get_es_hostname_config(MockConfigParser):
    result = MagicMock()
    result.__contains__.return_value = True
    result.__getitem__.return_value = {"es_endpoint": "foo"}
    MockConfigParser.ConfigParser.return_value = result
    assert utils.get_es_hostname() == "foo"


@patch("siem.utils.configparser")
def test_cget_es_hostname_config_raise_error(MockConfigParser):
    with pytest.raises(BaseException):
        result = MagicMock()
        result.__contains__.return_value = False
        MockConfigParser.ConfigParser.return_value = result
        assert utils.get_es_hostname()


def test_create_logtype_s3key_dict():
    config = MagicMock()
    config.sections.return_value = {"section": {"s3_key": "Foo"}}
    config.__getitem__.return_value = {"s3_key": "Foo"}
    result = utils.create_logtype_s3key_dict(config)
    assert result == {"section": re.compile("Foo")}


def test_get_logtype_from_s3key_no_data():
    assert utils.get_logtype_from_s3key("/", {}) == "nodata"


def test_get_logtype_from_s3key_no_match():
    assert (
        utils.get_logtype_from_s3key("foo/bar", {"section": re.compile("baz")})
        == "unknown"
    )


def test_get_logtype_from_s3key_match():
    assert (
        utils.get_logtype_from_s3key("foo/bar", {"section": re.compile("foo")})
        == "section"
    )


def test_sqs_queue_no_url():
    assert utils.sqs_queue(None) == None


@patch("siem.utils.boto3")
def test_sqs_queue(MockBoto):
    MockBoto.resource.return_value.Queue.return_value = "bar"
    assert utils.sqs_queue("foo") == "bar"


@patch("siem.utils.boto3")
def test_sqs_queue_fails_connection(MockBoto):
    with pytest.raises(Exception):
        MockBoto.resource.side_effect = Exception("Boom!")
        utils.sqs_queue("foo")


@patch("siem.utils.boto3")
@patch("siem.utils.AWS4Auth")
@patch("siem.utils.Elasticsearch")
@patch("siem.utils.RequestsHttpConnection")
def test_initialize_es_connection(MockRequest, MockEs, MockAWSAuth, MockBoto):
    MockEs.return_value = "Foo"
    assert utils.initialize_es_connection("es.region.com") == "Foo"
    MockBoto.Session().get_credentials.assert_called_once()
    MockAWSAuth.assert_called_once_with(
        MockBoto.Session().get_credentials().access_key,
        MockBoto.Session().get_credentials().secret_key,
        "region",
        "es",
        session_token=MockBoto.Session().get_credentials().token,
    )
    MockEs.assert_called_once_with(
        hosts=[{"host": "es.region.com", "port": 443}],
        http_auth=MockAWSAuth(),
        use_ssl=True,
        http_compress=True,
        verify_certs=True,
        retry_on_timeout=True,
        connection_class=MockRequest,
        timeout=60,
    )


@patch("siem.utils.os")
@patch("siem.utils.sys")
def test_find_user_custom_libs(MockSys, MockOs):
    MockOs.path.is_dir.return_value = True
    MockOs.listdir.return_value = ["sf_foo", "bar"]
    assert utils.find_user_custom_libs() == ["sf_foo"]
    MockSys.path.append.assert_called_once_with("/opt/siem")


@patch("siem.utils.os")
def test_find_user_custom_libs_no_path(MockOs):
    MockOs.path.is_dir.return_value = False
    assert utils.find_user_custom_libs() == []


@pytest.mark.parametrize(
    "time,expected",
    [
        ("20:45", "20.75"),
        ("00:00", "0.0"),
        ("24:00", "24.0"),
        ("24", "24"),
        ("0", "0"),
    ],
)
def test_timestr_to_hours(time, expected):
    assert utils.timestr_to_hours(time) == expected


def test_timestr_to_hours_exception():
    with pytest.raises(Exception):
        utils.timestr_to_hours(1000)


@patch("siem.utils.configparser")
def test_get_etl_config_exception(MockConfigParser):
    result = MagicMock()
    result.__getitem__.return_value = {}
    MockConfigParser.ConfigParser.return_value = result
    with pytest.raises(Exception):
        utils.get_etl_config()


@patch("siem.utils.configparser")
@patch("siem.utils.timestr_to_hours")
def test_get_etl_config(MockTimeStr, MockConfigParser):
    result = MagicMock()
    result.__getitem__.side_effect = [
        {"doc_id": {}},
        {"index_tz": "foo"},
        {"index_tz": "foo"},
        {"timestamp_tz": "bar"},
        {"timestamp_tz": "bar"},
    ]
    result.__iter__.return_value = ["foo"]
    MockConfigParser.ConfigParser.return_value = result
    assert utils.get_etl_config() == result
    MockTimeStr.assert_has_calls([call("foo"), call("bar")])


@patch("siem.utils.importlib")
def test_load_modules_on_memory_no_script(MockImport):
    utils.load_modules_on_memory({"foo": {}}, [])
    MockImport.assert_not_called()


@patch("siem.utils.importlib")
def test_load_modules_on_memory_mod(MockImport):
    utils.load_modules_on_memory({"foo-bar": {"script_ecs": "bar"}}, ["sf_foo_bar.py"])
    MockImport.import_module.assert_called_once_with("sf_foo_bar")


@patch("siem.utils.importlib")
def test_load_modules_on_memory_old_mod(MockImport):
    utils.load_modules_on_memory({"foo-bar": {"script_ecs": "bar"}}, ["sf_foo-bar.py"])
    MockImport.import_module.assert_called_once_with("sf_foo_bar")


@patch("siem.utils.importlib")
def test_load_modules_on_memory_no_usrlib(MockImport):
    utils.load_modules_on_memory({"foo-bar": {"script_ecs": "bar"}}, [])
    MockImport.import_module.assert_called_once_with("siem.sf_foo_bar")


@patch("siem.utils.importlib")
def test_load_sf_module_no_script(MockImport):
    assert utils.load_sf_module({}, {}, []) == None
    MockImport.assert_not_called()


@patch("siem.utils.importlib")
def test_load_sf_module_mod(MockImport):
    logfile = MagicMock()
    logfile.logtype.replace.return_value = "foo_bar"
    utils.load_sf_module(logfile, {"script_ecs": "bar"}, ["sf_foo_bar.py"])
    MockImport.import_module.assert_called_once_with("sf_foo_bar")


@patch("siem.utils.importlib")
def test_load_sf_module_old_mod(MockImport):
    logfile = MagicMock()
    logfile.logtype.replace.return_value = "foo-bar"
    utils.load_sf_module(logfile, {"script_ecs": "bar"}, ["sf_foo-bar.py"])
    MockImport.import_module.assert_called_once_with("sf_foo-bar")


@patch("siem.utils.importlib")
def test_load_sf_module_no_usrlib(MockImport):
    logfile = MagicMock()
    logfile.logtype.replace.return_value = "foo_bar"
    utils.load_sf_module(logfile, {"script_ecs": "bar"}, [])
    MockImport.import_module.assert_called_once_with("siem.sf_foo_bar")


def test_make_exclude_own_log_patterns_no_key():
    config = MagicMock()
    config.__getitem__.return_value.getboolean.return_value = False
    assert utils.make_exclude_own_log_patterns(config) == {}


def test_make_exclude_own_log_patterns():
    config = MagicMock()
    configBoolean = MagicMock()
    configBoolean.getboolean.return_value = True
    configUA = MagicMock()
    configUA.get.return_value = "Foo"
    config.__getitem__.side_effect = [configBoolean, configUA]
    assert utils.make_exclude_own_log_patterns(config) == {
        "cloudtrail": {"userAgent": re.compile(".*Foo.*")},
        "s3accesslog": {"UserAgent": re.compile(".*Foo.*")},
    }


def test_get_exclude_log_patterns_csv_filename_return_none():
    config = MagicMock()
    config.__getitem__.get.return_value = False
    assert utils.get_exclude_log_patterns_csv_filename(config) == None


@patch("siem.utils.os")
@patch("siem.utils.boto3")
def test_get_exclude_log_patterns_csv_filename_os_geoip(MockBoto, MockOs):
    config = MagicMock()
    config.__getitem__.return_value.get.return_value = "filename"
    MockOs.environ.__contains__.return_value = True
    MockOs.environ.get.return_value = "bucket"
    assert utils.get_exclude_log_patterns_csv_filename(config) == "/tmp/filename"
    MockBoto.resource().Bucket.assert_called_once_with("bucket")
    MockBoto.resource().Bucket().download_file.assert_called_once_with(
        "filename", "/tmp/filename"
    )


@patch("siem.utils.os")
@patch("siem.utils.boto3")
@patch("siem.utils.configparser")
def test_get_exclude_log_patterns_csv_filename_config_geoip(
    MockConfigParser, MockBoto, MockOs
):
    config = MagicMock()
    config.__getitem__.return_value.get.return_value = "filename"
    MockOs.environ.__contains__.return_value = False

    result = MagicMock()
    result.__contains__.return_value = True
    result.__getitem__.return_value = {"GEOIP_BUCKET": "bucket"}
    MockConfigParser.ConfigParser.return_value = result

    assert utils.get_exclude_log_patterns_csv_filename(config) == "/tmp/filename"
    MockBoto.resource().Bucket.assert_called_once_with("bucket")
    MockBoto.resource().Bucket().download_file.assert_called_once_with(
        "filename", "/tmp/filename"
    )


@patch("siem.utils.os")
@patch("siem.utils.boto3")
@patch("siem.utils.configparser")
def test_get_exclude_log_patterns_csv_filename_config_none(
    MockConfigParser, MockBoto, MockOs
):
    config = MagicMock()
    config.__getitem__.return_value.get.return_value = "filename"
    MockOs.environ.__contains__.return_value = False

    result = MagicMock()
    result.__contains__.return_value = False
    MockConfigParser.ConfigParser.return_value = result

    assert utils.get_exclude_log_patterns_csv_filename(config) == None
    MockBoto.resource().Bucket.assert_not_called()
    MockBoto.resource().Bucket().download_file.assert_not_called()


@patch("siem.utils.os")
@patch("siem.utils.boto3")
def test_get_exclude_log_patterns_csv_filename_os_exception(MockBoto, MockOs):
    config = MagicMock()
    config.__getitem__.return_value.get.return_value = "filename"
    MockOs.environ.__contains__.return_value = True
    MockOs.environ.get.return_value = "bucket"
    MockBoto.resource().Bucket().download_file.side_effect = Exception("Boom!")
    assert utils.get_exclude_log_patterns_csv_filename(config) == None


def test_merge_dotted_key_value_into_dict():
    result = utils.merge_dotted_key_value_into_dict(None, "foo.bar.baz", "quxx")
    assert result == {"foo": {"bar": {"baz": "quxx"}}}


def test_merge_csv_into_log_patterns_no_filename():
    assert utils.merge_csv_into_log_patterns({}, None) == {}


@patch("siem.utils.csv")
@patch("siem.utils.merge_dotted_key_value_into_dict")
def test_merge_csv_into_log_patterns_text_pattern(MockMergeDotted, MockCsv):
    with patch("builtins.open", mock_open(read_data="data")) as mock_file:

        MockCsv.DictReader.return_value = [
            {
                "field": "bar",
                "log_type": "foo",
                "pattern_type": "text",
                "pattern": "'^a.*$'",
            }
        ]
        MockMergeDotted.return_value = {"foo": {"bar": {"baz": "quxx"}}}
        assert utils.merge_csv_into_log_patterns({}, "foo.csv") == {
            "foo": {"foo": {"bar": {"baz": "quxx"}}}
        }
        mock_file.assert_called_with("foo.csv", "rt")
        MockMergeDotted.assert_called_with({}, "bar", re.compile("'\\^a\\.\\*\\$'$"))


@patch("siem.utils.csv")
@patch("siem.utils.merge_dotted_key_value_into_dict")
def test_merge_csv_into_log_patterns_non_text_pattern(MockMergeDotted, MockCsv):
    with patch("builtins.open", mock_open(read_data="data")) as mock_file:

        MockCsv.DictReader.return_value = [
            {
                "field": "bar",
                "log_type": "foo",
                "pattern_type": "not-text",
                "pattern": "foo",
            }
        ]
        MockMergeDotted.return_value = {"foo": {"bar": {"baz": "quxx"}}}
        assert utils.merge_csv_into_log_patterns({}, "foo.csv") == {
            "foo": {"foo": {"bar": {"baz": "quxx"}}}
        }
        mock_file.assert_called_with("foo.csv", "rt")
        MockMergeDotted.assert_called_with({}, "bar", re.compile("foo$"))


@patch("siem.utils.botocore")
def test_make_s3_session_config_with_user_agent(MockBoto):
    config = MagicMock()
    config.__getitem__.return_value.get.side_effect = ["agent", "ver"]
    result = utils.make_s3_session_config(config)
    MockBoto.config.Config.assert_called_with(user_agent="agent/ver")
    assert result == MockBoto.config.Config()


def test_make_s3_session_config_no_user_agent():
    config = MagicMock()
    config.__getitem__.return_value.get.side_effect = [False, "ver"]
    assert utils.make_s3_session_config(config) == None


@patch("siem.utils.os")
def test_show_local_dir(MockOs, caplog):
    MockOs.path().is_dir.return_value = True
    MockOs.listdir.return_value = "Foo.py"
    with caplog.at_level(logging.INFO):
        utils.show_local_dir()
    assert caplog.record_tuples == [
        (
            "service_undefined.siem.utils",
            20,
            "{'directory': '/tmp', 'files': 'Foo.py'}",
        ),
        (
            "service_undefined.siem.utils",
            20,
            "{'directory': '/opt', 'files': 'Foo.py'}",
        ),
        (
            "service_undefined.siem.utils",
            20,
            "{'directory': '/opt/siem', 'files': 'Foo.py'}",
        ),
    ]


@pytest.mark.parametrize(
    "data,expected",
    [
        (b"\x1f\x8b", "gzip"),
        (b"\x50\x4b", "zip"),
        (b"\x42\x5a", "bzip2"),
        (b"\x00\xF0", "binary"),
        (b"\xfd\xfe\xff", "text"),
        (b"abcdef", "text"),
    ],
)
def test_get_mime_type(data, expected):
    assert utils.get_mime_type(data) == expected


@pytest.mark.parametrize(
    "data,key,expected",
    [
        ({"a": {"b": {"c": 123}}}, "a.b.c", 123),
        ({"a": {"b": {"c": 123}}}, "a.b", {"c": 123}),
        ({"a": {"b": {"c": 123}}}, "x.y.z", None),
        ({"a": {"b": [{"d0": 123}, {"d1": 456}]}}, "a.b.0.d0", 123),
    ],
)
def test_value_from_nesteddict_by_dottedkey(data, key, expected):
    assert utils.value_from_nesteddict_by_dottedkey(data, key) == expected


@pytest.mark.parametrize(
    "data,key,expected",
    [
        ({"a": {"b": {"c1": 123, "c2": 456}}}, "a.b.c1 a.b.c2", 123),
        ({"a": {"b": {"c1": 123, "c2": 456}}}, "a.b.c2 a.b.c1", 456),
        ({"a": {"b": {"c1": 123, "c2": 456}}}, "z.z.z.z.z.z a.b.c1 a.b.c2", 123),
        (
            {"a": {"b": {"c1": 123, "c2": 456}}},
            ["z.z.z.z.z.z", "a.b.c1", "a.b.c2"],
            123,
        ),
    ],
)
def test_value_from_nesteddict_by_dottedkeylist(data, key, expected):
    assert utils.value_from_nesteddict_by_dottedkeylist(data, key) == expected


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("a", 123, {"a": "123"}),
        ("a.b.c.d.e", 123, {"a": {"b": {"c": {"d": {"e": "123"}}}}}),
        ("a.b.c", [123], {"a": {"b": {"c": "123"}}}),
        ("a.b.c", [123, 456], {"a": {"b": {"c": "123, 456"}}}),
        ("a.b.c", {"x": 1, "y": 2}, {"a": {"b": {"c": {"x": 1, "y": 2}}}}),
        ("a.b.c", '"', {"a": {"b": {"c": '"'}}}),
    ],
)
def test_put_value_into_nesteddict(key, value, expected):
    assert utils.put_value_into_nesteddict(key, value) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        ("a", "a"),
        ({"foo": "bar"}, {"foo": "bar"}),
        ({"foo": "bar-baz"}, {"foo": "bar-baz"}),
        ({"foo-bar": "baz"}, {"foo_bar": "baz"}),
        ([{"foo-bar": "baz"}], [{"foo_bar": "baz"}]),
    ],
)
def test_convert_keyname_to_safe_field(input, expected):
    assert utils.convert_keyname_to_safe_field(input) == expected


@pytest.mark.parametrize(
    "dict,expected",
    [
        ({"a": 111}, (True, "{a: 111}")),
        ({"a": 21112}, (False, None)),
        ({"aa": 222, "a": 111}, (True, "{a: 111}")),
        ({"x": {"y": {"z": 111}}}, (True, "{z: 111}")),
        ({"x": {"y": {"z": 222}}}, (False, None)),
        ({"x": {"hoge": 222, "y": {"z": 111}}}, (True, "{z: 111}")),
        ({"a": 222}, (False, None)),
    ],
)
def test_match_log_with_exclude_patterns(dict, expected):
    patterns = {
        "a": re.compile("^111$"),
        "b": re.compile("^222$"),
        "x": {"y": {"z": re.compile("^111$")}},
    }
    assert utils.match_log_with_exclude_patterns(dict, patterns) == expected


@pytest.mark.parametrize(
    "dicta,dictb,expected",
    [
        ({"a": 1, "b": 2}, {"b": 3, "c": 4}, {"a": 1, "b": 3, "c": 4}),
        (
            {"a": 1, "b": {"x": 10, "z": 30}},
            {"b": {"x": 10, "y": 20}, "c": 4},
            {"a": 1, "b": {"x": 10, "z": 30, "y": 20}, "c": 4},
        ),
    ],
)
def test_merge_dicts(dicta, dictb, expected):
    assert utils.merge_dicts(dicta, dictb) == expected
