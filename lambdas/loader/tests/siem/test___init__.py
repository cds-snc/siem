import datetime
import io
import re
import pytest

from siem import LogS3, LogParser

from unittest.mock import ANY, call, MagicMock, patch, PropertyMock


@pytest.fixture
@patch("siem.LogS3.extract_rawdata_from_s3obj")
@patch("siem.LogS3.extract_header_from_cwl")
@patch("siem.LogS3.extract_messages_from_cwl")
def MockLog(MockExtractMessage, MockExtractRawHeader, MockExtractRaw):
    data = MagicMock()
    MockExtractRaw.return_value = data
    MockExtractRawHeader.return_value = ["loggroup", "logstream", "cwl_accountid"]
    MockExtractMessage.return_value = data

    record = {"s3": {"bucket": {"name": "foo"}, "object": {"key": "bar"}}}
    logtype = ""
    logconfig = {
        "file_format": "multiline",
        "max_log_count": "max_log_count",
        "multiline_firstline": "multiline_firstline",
        "s3_key_ignored": "",
        "via_cwl": "via_cwl",
        "via_firelens": "via_firelens",
    }
    s3_client = "s3_client"
    sqs_queue = MagicMock(name="sqs_queue")
    return LogS3(record, logtype, logconfig, s3_client, sqs_queue)


@patch("siem.LogS3.extract_rawdata_from_s3obj")
@patch("siem.LogS3.extract_header_from_cwl")
@patch("siem.LogS3.extract_messages_from_cwl")
def test_logS3_init(MockExtractMessage, MockExtractRawHeader, MockExtractRaw):
    data = MagicMock()
    MockExtractRaw.return_value = data
    MockExtractRawHeader.return_value = ["loggroup", "logstream", "cwl_accountid"]
    MockExtractMessage.return_value = "bar"

    record = {"s3": {"bucket": {"name": "foo"}, "object": {"key": "bar"}}}
    logtype = ""
    logconfig = {
        "file_format": "multiline",
        "max_log_count": "max_log_count",
        "multiline_firstline": "multiline_firstline",
        "s3_key_ignored": "",
        "via_cwl": "via_cwl",
        "via_firelens": "via_firelens",
    }
    s3_client = "s3_client"
    sqs_queue = "sqs_queue"
    log = LogS3(record, logtype, logconfig, s3_client, sqs_queue)
    assert log.record == record
    assert log.logtype == logtype
    assert log.logconfig == logconfig
    assert log.s3_client == s3_client
    assert log.sqs_queue == sqs_queue
    assert log.s3bucket == "foo"
    assert log.s3key == "bar"
    assert log.file_format == "multiline"
    assert log.max_log_count == "max_log_count"
    assert log.via_cwl == "via_cwl"
    assert log.via_firelens == "via_firelens"
    assert log.loggroup == "loggroup"
    assert log.logstream == "logstream"
    assert log.cwl_accountid == "cwl_accountid"
    assert log.re_multiline_firstline == "multiline_firstline"
    assert log._LogS3__rawdata == "bar"
    MockExtractMessage.assert_called_once_with(data)


def test_logS3_iter_ignored(MockLog):
    MockLog.is_ignored = True
    a = [x for x in MockLog]
    assert a == []


@patch("siem.LogS3.logdata_generator")
def test_logS3_iter_low_log_count(MockGenerator, MockLog):
    MockLog.log_count = 0
    MockLog.max_log_count = 1
    MockGenerator.return_value = [1, 2, 3]
    a = [x for x in MockLog]
    assert a == [1, 2, 3]


@patch("siem.LogS3.logdata_generator")
def test_logS3_iter_no_sqs(MockGenerator, MockLog):
    MockLog.log_count = 1
    MockLog.max_log_count = 0
    MockLog.sqs_queue = None
    MockGenerator.return_value = [1, 2, 3]
    a = [x for x in MockLog]
    assert a == [1, 2, 3]


@patch("siem.LogS3.split_logs")
@patch("siem.LogS3.send_meta_to_sqs")
def test_logS3_iter_split(MockSendMeta, MockSplitLogs, MockLog):
    MockLog.log_count = 2
    MockLog.max_log_count = 1

    MockSplitLogs.return_value = ["foo"]
    MockSendMeta.return_value = 2

    a = [x for x in MockLog]
    assert a == []
    assert MockLog.is_ignored == True
    assert MockLog.total_log_count == 0
    assert (
        MockLog.ignored_reason == f"Log file was split into 2 pieces and sent to SQS."
    )


def test_logS3_is_ignored_bad_key(MockLog):
    MockLog.s3key = "/"
    assert LogS3.is_ignored.func(MockLog) == True
    assert MockLog.ignored_reason == f"this s3 key is just path, /"


def test_logS3_is_ignored_unkown_logtype(MockLog):
    MockLog.logtype = "unknown"
    assert LogS3.is_ignored.func(MockLog) == True
    assert MockLog.ignored_reason == f"unknown log type in S3 key, bar"


def test_logS3_is_ignored_ignored_key_match(MockLog):
    MockLog.logconfig["s3_key_ignored"] = re.compile("^bar$")
    assert LogS3.is_ignored.func(MockLog) == True
    assert (
        MockLog.ignored_reason
        == f"\"s3_key_ignored\" re.compile('^bar$') matched with bar"
    )


def test_logS3_is_ignored_ignored_no_key_match(MockLog):
    MockLog.logconfig["s3_key_ignored"] = re.compile("^foo$")
    assert LogS3.is_ignored.func(MockLog) == False


def test_logS3_log_count_end_not_0(MockLog):
    MockLog.end_number = 3
    MockLog.start_number = 2
    assert LogS3.log_count.func(MockLog) == 1


def test_logS3_log_count_no_logs(MockLog):
    MockLog.end_number = 0
    MockLog.file_format = ""
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 0
    MockLog.is_ignored = True
    MockLog.ignored_reason = "there are not any valid logs in S3 object"


@patch("siem.LogS3.rawdata")
def test_logS3_log_count_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = "csv"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.rawdata")
def test_logS3_log_count_text(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = "text"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.rawdata")
def test_logS3_log_count_firelens(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = ""
    MockLog.via_firelens = "via_firelens"
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.extract_logobj_from_json")
def test_logS3_log_count_json(MockLogObj, MockLog):
    MockLogObj.return_value = [2]
    MockLog.end_number = 0
    MockLog.file_format = "json"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.count_multiline_log")
def test_logS3_log_count_multiline(MockCountMultiLine, MockLog):
    MockCountMultiLine.return_value = 2
    MockLog.end_number = 0
    MockLog.file_format = "multiline"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


def test_logS3_rawdata(MockLog):
    data = MagicMock()
    MockLog._LogS3__rawdata = data
    assert MockLog.rawdata == data


@patch("siem.LogS3.rawdata")
def test_logS3_csv_header_with_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = ["foo", "bar"]
    MockLog.file_format = "csv"
    assert LogS3.csv_header.func(MockLog) == "foo"


def test_logS3_csv_header_no_csv(MockLog):
    MockLog.file_format = ""
    assert LogS3.csv_header.func(MockLog) == None


@patch("siem.utils.extract_aws_account_from_text")
def test_logS3_accountid_failed_extract(MockExtract, MockLog):
    MockExtract.return_value = False
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == None


@patch("siem.utils.extract_aws_account_from_text")
def test_logS3_accountid_extract(MockExtract, MockLog):
    MockExtract.return_value = "foo"
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == "foo"


def test_logS3_accountid_cwl_accountid(MockLog):
    MockLog.cwl_accountid = "foo"
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == "foo"


def test_logS3_accountid_cwe_accountid(MockLog):
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = "foo"
    assert LogS3.accountid.func(MockLog) == "foo"


@patch("siem.utils.extract_aws_region_from_text")
def test_logS3_region_failed_extract(MockExtract, MockLog):
    MockExtract.return_value = False
    MockLog.cwe_region = None
    assert LogS3.region.func(MockLog) == None


@patch("siem.utils.extract_aws_region_from_text")
def test_logS3_region_extract(MockExtract, MockLog):
    MockExtract.return_value = "foo"
    MockLog.cwe_region = None
    assert LogS3.region.func(MockLog) == "foo"


def test_logS3_region_cwe_region(MockLog):
    MockLog.cwe_region = "foo"
    assert LogS3.region.func(MockLog) == "foo"


def test_logS3_start_number(MockLog):
    MockLog.record = {"siem": {"start_number": 1}}
    assert LogS3.start_number.func(MockLog) == 1


def test_logS3_start_number_error(MockLog):
    MockLog.record = {"siem": {}}
    assert LogS3.start_number.func(MockLog) == 0


def test_logS3_end_number(MockLog):
    MockLog.record = {"siem": {"end_number": 1}}
    assert LogS3.end_number.func(MockLog) == 1


def test_logS3_end_number_error(MockLog):
    MockLog.record = {"siem": {}}
    assert LogS3.end_number.func(MockLog) == 0


def test_logS3_startmsg(MockLog):
    assert MockLog.startmsg() == {
        "end_number": 0,
        "logtype": "",
        "msg": "Invoked es-loader",
        "s3_bucket": "foo",
        "s3_key": "bar",
        "start_number": 0,
    }


@patch("siem.LogS3.rawdata")
def test_logS3_logdata_generator_text(MockRawData, MockLog):
    MockRawData.readlines.return_value = ["foo", "bar"]

    MockLog.file_format = "text"
    MockLog.logconfig = {"text_header_line_number": 0}

    MockLog.start_number = 0
    MockLog.log_count = 1
    MockLog.max_log_count = 1

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["foo"]
    assert MockLog.total_log_count == 1


@patch("siem.LogS3.rawdata")
def test_logS3_logdata_generator_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = ["foo", "bar"]

    MockLog.file_format = "csv"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 2

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["bar"]
    assert MockLog.total_log_count == 1


@patch("siem.LogS3.extract_logobj_from_json")
def test_logS3_logdata_generator_json(MockExtract, MockLog):
    MockExtract.return_value = ["foo", "bar"]

    MockLog.via_firelens = None
    MockLog.file_format = "json"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 3

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["foo", "bar"]
    assert MockLog.total_log_count == 2


@patch("siem.LogS3.extract_multiline_log")
def test_logS3_logdata_generator_multiline(MockExtract, MockLog):
    MockExtract.return_value = ["foo", "bar"]

    MockLog.via_firelens = None
    MockLog.file_format = "multiline"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 3

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["foo", "bar"]
    assert MockLog.total_log_count == 2


def test_logS3_logdata_generator_exception(MockLog):
    MockLog.via_firelens = None
    MockLog.file_format = "foo"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 3

    with pytest.raises(Exception):
        [x for x in MockLog.logdata_generator()]


def test_logS3_extract_header_from_cwl_empty(MockLog):
    data = MagicMock()
    data.read.return_value = ""
    assert MockLog.extract_header_from_cwl(data) == (None, None, None)


@patch("siem.json")
def test_logS3_extract_header_from_cwl(MockJson, MockLog):
    data = MagicMock()
    MockJson.JSONDecoder().raw_decode.side_effect = [
        ({"messageType": "CONTROL_MESSAGE"}, 1),
        ({"messageType": "", "logGroup": "foo", "logStream": "bar", "owner": "baz"}, 2),
    ]
    assert MockLog.extract_header_from_cwl(data) == ("foo", "bar", "baz")


@patch("siem.json")
def test_logS3_extract_messages_from_cwl(MockJson, MockLog):
    data = MagicMock()
    data.read.return_value = "11"
    MockJson.JSONDecoder().raw_decode.side_effect = [
        ({"messageType": "CONTROL_MESSAGE"}, 1),
        ({"messageType": "", "logEvents": [{"message": "foo"}]}, 2),
    ]
    result = MockLog.extract_messages_from_cwl(data)
    assert result.read() == "foo\n"


def test_logS3_extract_rawdata_from_s3obj_exception(MockLog):
    MockLog.s3key = "foo"
    MockLog.s3_client = MagicMock()
    MockLog.s3_client.get_object.return_value = Exception("Boom!")
    with pytest.raises(Exception):
        MockLog.extract_rawdata_from_s3obj()


def test_logS3_extract_rawdata_from_s3obj_size_too_small(MockLog):
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"ResponseMetadata": {"HTTPHeaders": {"content-length": 0}}}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == None
    MockLog.s3_client.get_object.assert_called_once_with(Bucket="foo", Key="bar")
    assert MockLog.is_ignored == True


@patch("siem.utils.get_mime_type")
def test_logS3_extract_rawdata_from_s3obj_mime_exception(MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "unkown"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    with pytest.raises(Exception):
        MockLog.extract_rawdata_from_s3obj()


@patch("siem.utils.get_mime_type")
@patch("siem.gzip")
def test_logS3_extract_rawdata_from_s3obj_gzip(MockGZip, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "gzip"
    MockGZip.open.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.utils.get_mime_type")
@patch("siem.io.TextIOWrapper")
def test_logS3_extract_rawdata_from_s3obj_text(MockText, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "text"
    MockText.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.utils.get_mime_type")
@patch("siem.zipfile")
@patch("builtins.open")
def test_logS3_extract_rawdata_from_s3obj_zip(
    MockOpen, _MockZip, MockGetMimeType, MockLog
):
    MockGetMimeType.return_value = "zip"
    MockOpen.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.utils.get_mime_type")
@patch("siem.bz2")
def test_logS3_extract_rawdata_from_s3obj_bzip2(MockBz2, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "bzip2"
    MockBz2.open.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_logS3_extract_logobj_from_json_no_delimiter_count(MockStrip, MockLog):
    MockStrip.side_effect = [{"event": 1}, {"event": 2}]
    MockLog.logconfig = {"json_delimiter": False}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json()]
    assert a == [1, 2]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_logS3_extract_logobj_from_json_delimiter_count(MockStrip, MockLog):
    MockStrip.side_effect = [
        {"|": [{"event": 1}, {"event": 2}]},
        {"|": [{"event": 3}, {"event": 4}]},
    ]
    MockLog.logconfig = {"json_delimiter": "|"}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json()]
    assert a == [2, 4]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_logS3_extract_logobj_from_json_no_delimiter_no_count(MockStrip, MockLog):
    MockStrip.side_effect = [{"event": 1}, {"event": 2}]
    MockLog.logconfig = {"json_delimiter": False}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json(mode="foo", end=2)]
    assert a == [{"event": 1}, {"event": 2}]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_logS3_extract_logobj_from_json_delimiter_no_count(MockStrip, MockLog):
    MockStrip.side_effect = [
        {"|": [{"event": 1}, {"event": 2}]},
        {"|": [{"event": 3}, {"event": 4}]},
    ]
    MockLog.logconfig = {"json_delimiter": "|"}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json(mode="foo", end=2)]
    assert a == [{"event": 1}, {"event": 2}]


def test_logS3_match_multiline_firstline_true(MockLog):
    MockLog.re_multiline_firstline = re.compile("^foo$")
    assert MockLog.match_multiline_firstline("foo") == True


def test_logS3_match_multiline_firstline_false(MockLog):
    MockLog.re_multiline_firstline = re.compile("^foo$")
    assert MockLog.match_multiline_firstline("bar") == False


@patch("siem.LogS3.match_multiline_firstline")
def test_logS3_count_multiline_log(MockMatch, MockLog):
    MockLog.rawdata.__iter__.return_value = ["foo", "bar"]
    MockMatch.side_effect = [True, False]
    assert MockLog.count_multiline_log() == 1


@patch("siem.LogS3.match_multiline_firstline")
def test_logS3_extract_multiline_log(MockMatch, MockLog):
    MockLog.rawdata.__iter__.return_value = ["foo", "bar"]
    MockMatch.side_effect = [True, False]
    a = [x for x in MockLog.extract_multiline_log(end=2)]
    assert a == ["foobar"]


def test_logS3_check_cwe_and_strip_header_no_match(MockLog):
    assert MockLog.check_cwe_and_strip_header({}) == {}


def test_logS3_check_cwe_and_strip_header(MockLog):
    data = {
        "detail-type": "detail-type",
        "resources": "resources",
        "account": "account",
        "region": "region",
        "detail": "detail",
    }
    assert MockLog.check_cwe_and_strip_header(data) == "detail"
    assert MockLog.cwe_accountid == "account"
    assert MockLog.cwe_region == "region"


@pytest.mark.parametrize(
    "log_count,max_log_count,expected",
    [
        (1, 1, [(1, 1)]),
        (1, 2, [(1, 1)]),
        (2, 2, [(1, 2)]),
        (2, 1, [(1, 1), (2, 2)]),
        (3, 2, [(1, 2), (3, 3)]),
        (2, 3, [(1, 2)]),
    ],
)
def test_logS3_split_logs(log_count, max_log_count, expected, MockLog):
    assert MockLog.split_logs(log_count, max_log_count) == expected


def test_logS3_send_meta_to_sqs_exception(MockLog):
    MockLog.sqs_queue.send_messages.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": 500}
    }
    with pytest.raises(Exception):
        MockLog.send_meta_to_sqs([(1, 2)])


def test_logS3_send_meta_to_sqs(MockLog):
    MockLog.sqs_queue.send_messages.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": 200}
    }
    MockLog.send_meta_to_sqs([(1, 2)]) == 2
    MockLog.sqs_queue.send_messages.assert_called_once_with(
        Entries=[
            {
                "Id": "num_1",
                "MessageBody": '{"siem": {"start_number": 1, "end_number": 2}, "s3": {"bucket": {"name": "foo"}, "object": {"key": "bar"}}}',
            }
        ]
    )


@pytest.fixture
def MockParser(MockLog):
    logfile = MockLog
    logconfig = {"index_tz": 1, "timestamp_nano": 1234, "timestamp_tz": -5}
    sf_module = MagicMock(name="sf_module")
    geodb_instance = MagicMock(name="geodb_instance")
    exclude_log_patterns = MagicMock(name="exclude_log_patterns")

    return LogParser(
        logfile, logconfig, sf_module, geodb_instance, exclude_log_patterns
    )


def test_parser_init(MockParser, MockLog):
    assert MockParser.logfile == MockLog
    assert MockParser.sf_module._extract_mock_name() == "sf_module"
    assert MockParser.geodb_instance._extract_mock_name() == "geodb_instance"
    assert (
        MockParser.exclude_log_patterns._extract_mock_name() == "exclude_log_patterns"
    )

    assert MockParser.logtype == ""
    assert MockParser.logtype == ""
    assert MockParser.s3bucket == "foo"
    assert MockParser.logformat == "multiline"
    assert MockParser.header == None
    assert MockParser.accountid == "cwl_accountid"
    assert MockParser.region == None
    assert MockParser.loggroup == "loggroup"
    assert MockParser.logstream == "logstream"
    assert MockParser.via_firelens == "via_firelens"

    assert MockParser.timestamp_tz == datetime.timezone(
        datetime.timedelta(days=-1, seconds=68400)
    )
    assert MockParser.index_tz == datetime.timezone(datetime.timedelta(seconds=3600))
    assert MockParser.has_nanotime == 1234


@patch("siem.LogParser.logdata_to_dict")
@patch("siem.LogParser.is_ignored")
@patch("siem.LogParser.set_skip_normalization")
@patch("siem.LogParser.get_timestamp")
@patch("siem.LogParser.add_basic_field")
@patch("siem.LogParser.clean_multi_type_field")
@patch("siem.LogParser.transform_to_ecs")
@patch("siem.LogParser.transform_by_script")
@patch("siem.LogParser.enrich")
def test_parser_call(
    MockEnrich,
    MockTransformByScript,
    MockTransformByECS,
    MockCleanMultiField,
    MockAddBasicField,
    MockGetTimeStamp,
    MockSetSkip,
    _MockIsIgnored,
    MockLogtoDict,
    MockParser,
):

    MockLogtoDict.return_value = "logdata_to_dict"
    MockSetSkip.return_value = "set_skip_normalization"
    MockGetTimeStamp.return_value = "get_timestamp"

    MockParser.is_ignored = False

    MockParser.__call__({})

    assert MockParser.logdata == {}
    assert MockParser._LogParser__logdata_dict == "logdata_to_dict"
    assert MockParser._LogParser__skip_normalization == "set_skip_normalization"
    assert MockParser._LogParser__timestamp == "get_timestamp"

    MockLogtoDict.assert_called_once()
    MockSetSkip.assert_called_once()
    MockGetTimeStamp.assert_called_once()
    MockAddBasicField.assert_called_once()
    MockCleanMultiField.assert_called_once()
    MockTransformByECS.assert_called_once()
    MockTransformByScript.assert_called_once()
    MockEnrich.assert_called_once()


def test_parser_is_ignored_key(MockParser):
    MockParser._LogParser__logdata_dict = {"ignored_reason": "bar", "is_ignored": "foo"}
    assert MockParser.is_ignored == True
    assert MockParser.ignored_reason == "bar"


@patch("siem.utils.match_log_with_exclude_patterns")
def test_parser_is_ignored_logtype_in_ignored(MockMatch, MockParser):
    MockMatch.return_value = (True, "fizz")
    MockParser._LogParser__logdata_dict = {}
    MockParser.logtype = "fizz"
    MockParser.exclude_log_patterns = {"fizz": "fizz"}
    assert MockParser.is_ignored == True
    assert MockParser.ignored_reason == "matched fizz with exclude_log_patterns"


def test_parser_is_ignored_logtype_no_match(MockParser):
    MockParser._LogParser__logdata_dict = {}
    assert MockParser.is_ignored == False


def test_parser_timestamp(MockParser):
    MockParser._LogParser__timestamp = "foo"
    assert MockParser.timestamp == "foo"


def test_parser_event_ingested(MockParser):
    MockParser._LogParser__event_ingested = "foo"
    assert MockParser.event_ingested == "foo"


def test_parser_doc_id_no_suffix(MockParser):
    MockParser._LogParser__logdata_dict = {"@id": "@id"}
    MockParser.logconfig = {"doc_id_suffix": None}
    assert MockParser.doc_id == "@id"


def test_parser_doc_id_with_suffix(MockParser):
    MockParser._LogParser__logdata_dict = {"__doc_id_suffix": "suffix", "@id": "@id"}
    MockParser.logconfig = {"doc_id_suffix": None}
    assert MockParser.doc_id == "@id_suffix"


@patch("siem.utils.value_from_nesteddict_by_dottedkey")
def test_parser_doc_id_in_config(MockValues, MockParser):
    MockValues.return_value = "suffix_from_config"
    MockParser._LogParser__logdata_dict = {"@id": "@id"}
    MockParser.logconfig = {"doc_id_suffix": "doc_id_suffix"}
    assert MockParser.doc_id == "@id_suffix_from_config"


def test_parser_indexname_in_logdata(MockParser):
    MockParser._LogParser__logdata_dict = {"__index_name": "index-name"}
    MockParser.logconfig = {"index_rotation": "auto"}
    assert MockParser.indexname == "index-name"


def test_parser_indexname_in_logconfig(MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"index_rotation": "auto", "index_name": "index-name"}
    assert MockParser.indexname == "index-name"


def test_parser_indexname_event_ingested(MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {
        "index_rotation": "foo",
        "index_name": "index-name",
        "index_time": {"event_ingested": "event_ingested"},
        "index_tz": 1,
    }
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    assert MockParser.indexname == "index-name" + time.strftime("-%Y")


def test_parser_indexname_no_event_ingested(MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {
        "index_rotation": "foo",
        "index_name": "index-name",
        "index_time": {},
        "index_tz": 1,
    }
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    assert MockParser.indexname == "index-name" + time.strftime("-%Y")


@pytest.mark.parametrize(
    "period,expected",
    [
        ("daily", "-%Y-%m-%d"),
        ("weekly", "-%Y-w%W"),
        ("monthly", "-%Y-%m"),
        ("annually", "-%Y"),
    ],
)
def test_parser_indexname_rotation(period, expected, MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {
        "index_rotation": period,
        "index_name": "index-name",
        "index_time": {},
        "index_tz": 1,
    }
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    assert MockParser.indexname == "index-name" + time.strftime(expected)


@patch("siem.LogParser.del_none")
def test_parser_json(MockDelNone, MockParser):
    MockParser._LogParser__logdata_dict = {"foo": "bar"}
    MockDelNone.return_value = {"foo": "bar"}
    assert MockParser.json == '{"foo": "bar"}'


@patch("siem.LogParser.del_none")
@patch("siem.LogParser.truncate_big_field")
def test_parser_json_too_big(MockTruncateBig, MockDelNone, MockParser):
    MockParser._LogParser__logdata_dict = {"foo": "bar"}
    big_data = []
    for _ in range(10_000):
        big_data.append({"foo": "bar"})
    MockDelNone.return_value = big_data
    MockTruncateBig.return_value = {"foo": "bar"}
    assert MockParser.json == '{"foo": "bar"}'
    MockTruncateBig.assert_called_once_with(big_data)


@patch("siem.LogParser.get_log_and_meta_from_firelens")
@patch("siem.LogParser.validate_logdata_in_firelens")
def test_parser_logdata_to_dict_invalid_firelens(
    MockValidateFirelens, MockGetFirelens, MockParser
):
    MockParser.via_firelens = True
    MockGetFirelens.return_value = ("data", {})
    MockValidateFirelens.return_value = ("invalid_data", False)
    assert MockParser.logdata_to_dict({}) == "invalid_data"


@patch("siem.LogParser.get_log_and_meta_from_firelens")
@patch("siem.LogParser.validate_logdata_in_firelens")
def test_parser_logdata_to_dict_valid_firelens(
    MockValidateFirelens, MockGetFirelens, MockParser
):
    MockParser.via_firelens = True
    MockParser.logformat = "Other"
    MockGetFirelens.return_value = ("data", {"metadata": "metadata"})
    MockValidateFirelens.return_value = ("valid_data", True)
    assert MockParser.logdata_to_dict({}) == {"metadata": "metadata"}


@patch("siem.utils.convert_keyname_to_safe_field")
def test_parser_logdata_to_dict_using_csv(MockConvert, MockParser):
    MockParser.via_firelens = False
    MockParser.logformat = "csv"
    MockParser.header = "1,2"
    MockConvert.side_effect = lambda x: x
    assert MockParser.logdata_to_dict("a,b") == {"1,2": "a,b"}


def test_parser_logdata_to_dict_using_json(MockParser):
    MockParser.via_firelens = False
    MockParser.logformat = "json"
    assert MockParser.logdata_to_dict({"data": "data"}) == {"data": "data"}


@patch("siem.LogParser.text_logdata_to_dict")
def test_parser_logdata_to_dict_using_text(MockConvert, MockParser):
    MockParser.via_firelens = False
    MockParser.logformat = "text"
    MockConvert.side_effect = lambda x: x
    assert MockParser.logdata_to_dict({"data": "data"}) == {"data": "data"}


@patch("siem.LogParser.text_logdata_to_dict")
def test_parser_logdata_to_dict_using_multiline(MockConvert, MockParser):
    MockParser.via_firelens = False
    MockParser.logformat = "multiline"
    MockConvert.side_effect = lambda x: x
    assert MockParser.logdata_to_dict({"data": "data"}) == {"data": "data"}


@patch("siem.utils.merge_dicts")
def test_parser_add_basic_field_with_json(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logformat = "json"
    MockParser.logdata = {"data": "data"}
    MockParser.logtype = "logtype"
    MockParser.loggroup = False
    MockParser.logconfig = {"doc_id": None}
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    MockParser._LogParser__skip_normalization = False
    MockParser._LogParser__logdata_dict = {}
    MockParser.add_basic_field()
    assert MockParser._LogParser__logdata_dict == {
        "@id": "2249253cc493568d9e75bd7f09dabd9c",
        "@log_s3bucket": "foo",
        "@log_s3key": "bar",
        "@log_type": "logtype",
        "@message": '{"data": "data"}',
        "@timestamp": time.isoformat(),
        "event": {"ingested": time.isoformat(), "module": "logtype"},
    }


@patch("siem.utils.merge_dicts")
def test_parser_add_basic_field_string(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logformat = "text"
    MockParser.logdata = "data;data"
    MockParser.logtype = "logtype"
    MockParser.loggroup = False
    MockParser.logconfig = {"doc_id": None}
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    MockParser._LogParser__skip_normalization = False
    MockParser._LogParser__logdata_dict = {}
    MockParser.add_basic_field()
    assert MockParser._LogParser__logdata_dict == {
        "@id": "0c8e870a4075329d49a96ac881e8fecf",
        "@log_s3bucket": "foo",
        "@log_s3key": "bar",
        "@log_type": "logtype",
        "@message": "data;data",
        "@timestamp": time.isoformat(),
        "event": {"ingested": time.isoformat(), "module": "logtype"},
    }


@patch("siem.utils.merge_dicts")
def test_parser_add_basic_field_skip_normalization(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logformat = "text"
    MockParser.logdata = "data;data"
    MockParser.logtype = "logtype"
    MockParser.loggroup = False
    MockParser.logconfig = {"doc_id": None}
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    MockParser._LogParser__skip_normalization = True
    MockParser._LogParser__logdata_dict = {}
    MockParser.add_basic_field()
    assert MockParser._LogParser__logdata_dict == {
        "@id": "539351b2130710bdb396afe3fafdbf4f",
        "@log_s3bucket": "foo",
        "@log_s3key": "bar",
        "@log_type": "logtype",
        "@message": "data;data",
        "@timestamp": time.isoformat(),
        "event": {"ingested": time.isoformat(), "module": "logtype"},
    }


@patch("siem.utils.merge_dicts")
def test_parser_add_basic_field_with_docid(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logformat = "text"
    MockParser.logdata = {"abcd": "data;data"}
    MockParser.logtype = "logtype"
    MockParser.loggroup = False
    MockParser.logconfig = {"doc_id": "abcd"}
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    MockParser._LogParser__skip_normalization = False
    MockParser._LogParser__logdata_dict = {"abcd": "data;data"}
    MockParser.add_basic_field()
    assert MockParser._LogParser__logdata_dict == {
        "@id": "data;data",
        "@log_s3bucket": "foo",
        "@log_s3key": "bar",
        "@log_type": "logtype",
        "@message": "{'abcd': 'data;data'}",
        "@timestamp": time.isoformat(),
        "event": {"ingested": time.isoformat(), "module": "logtype"},
    }


@patch("siem.utils.merge_dicts")
def test_parser_add_basic_field_with_loggroup(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logformat = "text"
    MockParser.logdata = {"abcd": "data;data"}
    MockParser.logtype = "logtype"
    MockParser.loggroup = "Foo"
    MockParser.logstream = "Bar"
    MockParser.logconfig = {"doc_id": "abcd"}
    time = datetime.datetime.now()
    MockParser._LogParser__timestamp = time
    MockParser._LogParser__event_ingested = time
    MockParser._LogParser__skip_normalization = False
    MockParser._LogParser__logdata_dict = {"abcd": "data;data"}
    MockParser.add_basic_field()
    assert MockParser._LogParser__logdata_dict == {
        "@id": "data;data",
        "@log_s3bucket": "foo",
        "@log_s3key": "bar",
        "@log_type": "logtype",
        "@log_group": "Foo",
        "@log_stream": "Bar",
        "@message": "{'abcd': 'data;data'}",
        "@timestamp": time.isoformat(),
        "event": {"ingested": time.isoformat(), "module": "logtype"},
    }


@patch("siem.utils.merge_dicts")
def test_parser_clean_multi_type_field_no_multifieldkeys(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"json_to_text": ""}
    MockParser.clean_multi_type_field()
    assert MockParser._LogParser__logdata_dict == {}


@patch("siem.utils.merge_dicts")
@patch("siem.utils.value_from_nesteddict_by_dottedkey")
def test_parser_clean_multi_type_field_no_values(MockValues, MockMerge, MockParser):
    MockValues.return_value = False
    MockMerge.side_effect = lambda _x, y: y
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"json_to_text": "foo bar"}
    MockParser.clean_multi_type_field()
    assert MockParser._LogParser__logdata_dict == {}
    MockValues.assert_has_calls([call({}, "foo"), call({}, "bar")])


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "{'foo': 0}"),
        ("{'bar': '0'}", "{'foo': \"{'bar': '0'}\"}"),
        ({"foo": {"bar": "0"}}, "{'foo': {'foo': {'bar': '0'}}}"),
    ],
)
@patch("siem.utils.merge_dicts")
@patch("siem.utils.value_from_nesteddict_by_dottedkey")
@patch("siem.utils.put_value_into_nesteddict")
def test_parser_clean_multi_type_field_value_found(
    MockPutValues,
    MockValues,
    MockMerge,
    MockParser,
    value,
    expected,
):
    MockValues.return_value = {"foo": value}
    MockMerge.side_effect = lambda _x, y: y
    MockPutValues.side_effect = lambda _x, y: y
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"json_to_text": "foo"}
    MockParser.clean_multi_type_field()
    assert MockParser._LogParser__logdata_dict == expected


def test_parser_transform_to_ecs_no_keys(MockParser):
    data = {"cloud_provider": None, "ecs": "", "ecs_version": "foo", "static_ecs": None}
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {"ecs": {"version": "foo"}}


def test_parser_transform_to_ecs_with_cloud_provider(MockParser):
    data = {
        "cloud_provider": "foo",
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "account": {"id": "cwl_accountid"},
            "provider": "foo",
            "region": "unknown",
        },
        "ecs": {"version": "foo"},
    }


@patch("siem.utils.merge_dicts")
@patch("siem.utils.value_from_nesteddict_by_dottedkey")
@patch("siem.utils.put_value_into_nesteddict")
def test_parser_transform_to_ecs_with_ip_key(
    MockPutValues, MockValues, MockMerge, MockParser
):
    data = {
        "cloud_provider": "foo",
        "ecs": "foo.ip",
        "ecs_version": "foo",
        "static_ecs": None,
        "foo.ip": "127.0.0.1",
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockValues.side_effect = lambda _x, y: y
    MockMerge.side_effect = lambda _x, y: y
    MockPutValues.side_effect = lambda _x, y: {"ip": y}
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {"ip": "127.0.0.1"}


def test_parser_transform_to_ecs_with_account_id_set(MockParser):
    data = {
        "cloud_provider": None,
        "cloud": {"account": {"id": "unknown"}},
        "ecs": "cloud",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {"account": {"id": "unknown"}}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "account": {
            "account": {"id": "cwl_accountid"},
            "id": "unknown",
            "region": "unknown",
        },
        "cloud": {
            "account": {"id": "cwl_accountid"},
            "id": "unknown",
            "region": "unknown",
        },
        "ecs": {"version": "foo"},
    }


def test_parser_transform_to_ecs_no_account_id(MockParser):
    data = {
        "cloud_provider": "foo",
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.accountid = False
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "account": {"id": "unknown"},
            "provider": "foo",
            "region": "unknown",
        },
        "ecs": {"version": "foo"},
    }


def test_parser_transform_to_ecs_region_set(MockParser):
    data = {
        "cloud_provider": None,
        "cloud": {"region": "foo"},
        "ecs": "cloud",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {"cloud": {"region": "foo"}}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "region": "foo",
        },
        "ecs": {"version": "foo"},
    }


def test_parser_transform_to_ecs_region_set_in_class(MockParser):
    data = {
        "cloud_provider": "foo",
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.region = "Bar"
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "account": {"id": "cwl_accountid"},
            "provider": "foo",
            "region": "Bar",
        },
        "ecs": {"version": "foo"},
    }


def test_parser_transform_to_ecs_region_unknown(MockParser):
    data = {
        "cloud_provider": "foo",
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "account": {"id": "cwl_accountid"},
            "provider": "foo",
            "region": "unknown",
        },
        "ecs": {"version": "foo"},
    }


def test_parser_transform_to_ecs_task_arn(MockParser):
    data = {
        "cloud_provider": "foo",
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": None,
    }
    MockParser._LogParser__logdata_dict = {
        "container_id": "container_id",
        "container_name": "container_name",
        "ec2_instance_id": "i-id",
        "ecs_task_arn": "a:b:c:d:e",
    }
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {
            "account": {"id": "e"},
            "instance": {"id": "i-id"},
            "provider": "foo",
            "region": "d",
        },
        "container": {"id": "container_id", "name": "container_name"},
        "container_id": "container_id",
        "container_name": "container_name",
        "ecs": {"version": "foo"},
        "ec2_instance_id": "i-id",
        "ecs_task_arn": "a:b:c:d:e",
    }


def test_parser_transform_to_ecs_static_ecs_keys(MockParser):
    data = {
        "cloud_provider": None,
        "cloud": {"foo": "bar"},
        "ecs": "",
        "ecs_version": "foo",
        "static_ecs": "cloud",
    }
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = data
    MockParser.transform_to_ecs()
    assert MockParser._LogParser__logdata_dict == {
        "cloud": {"foo": "bar"},
        "ecs": {"version": "foo"},
    }


def test_parser_transform_by_script_key_set(MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"script_ecs": "foo"}
    module = MagicMock()
    module.transform.return_value = {"foo": "bar"}
    MockParser.sf_module = module
    MockParser.transform_by_script()
    assert MockParser._LogParser__logdata_dict == {"foo": "bar"}
    module.transform.assert_called_once_with({})


def test_parser_transform_by_script_key_not_set(MockParser):
    MockParser._LogParser__logdata_dict = {}
    MockParser.logconfig = {"script_ecs": None}
    module = MagicMock()
    MockParser.sf_module = module
    MockParser.transform_by_script()
    assert MockParser._LogParser__logdata_dict == {}
    module.transform.assert_not_called()


@patch("siem.utils.merge_dicts")
def test_parser_enrich_handles_key_errors(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logconfig = {"geoip": "foo bar"}
    MockParser._LogParser__logdata_dict = {"foo": {"ip": "127.0.0.1"}}
    geodb = MagicMock()
    geodb.check_ipaddress.side_effect = [("Foo", "Bar")]
    MockParser.geodb_instance = geodb
    MockParser.enrich()
    assert MockParser._LogParser__logdata_dict == {"foo": {"as": "Bar", "geo": "Foo"}}
    geodb.check_ipaddress.assert_has_calls([call("127.0.0.1")])


@patch("siem.utils.merge_dicts")
def test_parser_enrich_handles_just_asn(MockMerge, MockParser):
    MockMerge.side_effect = lambda _x, y: y
    MockParser.logconfig = {"geoip": "foo bar"}
    MockParser._LogParser__logdata_dict = {"foo": {"ip": "127.0.0.1"}}
    geodb = MagicMock()
    geodb.check_ipaddress.side_effect = [(None, "Bar")]
    MockParser.geodb_instance = geodb
    MockParser.enrich()
    assert MockParser._LogParser__logdata_dict == {"foo": {"as": "Bar"}}
    geodb.check_ipaddress.assert_has_calls([call("127.0.0.1")])


@patch("siem.json")
def test_parser_get_log_and_meta_from_firelens_not_populated(MockJson, MockParser):
    data = {"log": "log"}
    MockJson.loads.return_value = data
    MockParser.logdata = data
    result_log, result_dic = MockParser.get_log_and_meta_from_firelens()
    assert result_log == "log"
    assert result_dic == {
        "container_id": None,
        "container_name": None,
        "container_source": None,
        "ecs_cluster": None,
        "ecs_task_arn": None,
        "ecs_task_definition": None,
    }


@patch("siem.json")
def test_parser_get_log_and_meta_from_firelens(MockJson, MockParser):
    data = {
        "log": "log",
        "container_id": "container_name",
        "container_name": "container_name",
        "source": "container_source",
        "ecs_cluster": "ecs_cluster",
        "ecs_task_arn": "ecs_task_arn",
        "ecs_task_definition": "ecs_task_definition",
        "ec2_instance_id": "ec2_instance_id",
    }
    MockJson.loads.return_value = data
    MockParser.logdata = data
    result_log, result_dic = MockParser.get_log_and_meta_from_firelens()
    assert result_log == "log"
    assert result_dic == {
        "container_id": "container_name",
        "container_name": "container_name",
        "container_source": "container_source",
        "ecs_cluster": "ecs_cluster",
        "ecs_task_arn": "ecs_task_arn",
        "ecs_task_definition": "ecs_task_definition",
        "ec2_instance_id": "ec2_instance_id",
    }


def test_parser_validate_logdata_in_firelens_no_match(MockParser):
    meta = {"container_source": "container_source"}
    MockParser.logformat = "text"
    assert MockParser.validate_logdata_in_firelens("foo", meta) == ("foo", True)


def test_parser_validate_logdata_in_firelens_container_source_stderr_ignored(
    MockParser,
):
    meta = {"container_source": "stderr"}
    MockParser.logconfig = {"ignore_container_stderr": True}
    MockParser.logformat = "text"
    assert MockParser.validate_logdata_in_firelens("foo", meta) == (
        {"is_ignored": True, "ignored_reason": "log is container's stderr"},
        False,
    )


def test_parser_validate_logdata_in_firelens_container_source_stderr_not_ignored(
    MockParser,
):
    meta = {"container_source": "stderr"}
    MockParser.logconfig = {"ignore_container_stderr": False}
    MockParser.logformat = "text"
    assert MockParser.validate_logdata_in_firelens("foo", meta) == (
        {
            "container_source": "stderr",
            "__skip_normalization": True,
            "error": {"message": "foo"},
        },
        False,
    )


def test_parser_validate_logdata_in_firelens_bad_json(MockParser):
    meta = {"container_source": "container_source"}
    MockParser.logformat = "json"
    assert MockParser.validate_logdata_in_firelens("foo", meta) == (
        {
            "container_source": "container_source",
            "__skip_normalization": True,
            "error": {"message": "Invalid file format found during parsing"},
        },
        False,
    )


def test_parser_validate_logdata_in_firelens_good_json(MockParser):
    meta = {"container_source": "container_source"}
    MockParser.logformat = "json"
    assert MockParser.validate_logdata_in_firelens('{"foo": "bar"}', meta) == (
        {"foo": "bar"},
        True,
    )


def test_parser_text_logdata_to_dict_pattern_missing(MockParser):
    MockParser.logconfig = {}
    with pytest.raises(Exception):
        MockParser.text_logdata_to_dict({})


def test_parser_text_logdata_to_dict_no_good_pattern(MockParser):
    MockParser.logconfig = {"log_pattern": "foo"}
    with pytest.raises(Exception):
        MockParser.text_logdata_to_dict({})


def test_parser_text_logdata_to_dict_no_match(MockParser):
    MockParser.logconfig = {"log_pattern": re.compile("d+")}
    with pytest.raises(Exception):
        assert MockParser.text_logdata_to_dict("abcd") == {"key": "foo", "value": "bar"}


def test_parser_text_logdata_to_dict_match(MockParser):
    MockParser.logconfig = {"log_pattern": re.compile(r"(?P<key>\w+)=(?P<value>\w+)")}
    assert MockParser.text_logdata_to_dict("foo=bar") == {"key": "foo", "value": "bar"}


def test_parser_set_skip_normalization_set(MockParser):
    MockParser._LogParser__logdata_dict = {"__skip_normalization": True}
    assert MockParser.set_skip_normalization() == True
    assert MockParser._LogParser__logdata_dict == {}


def test_parser_set_skip_normalization_not_set(MockParser):
    MockParser._LogParser__logdata_dict = {}
    assert MockParser.set_skip_normalization() == False
    assert MockParser._LogParser__logdata_dict == {}


@patch("siem.utils.convert_timestr_to_datetime")
def test_parser_get_timestamp_not_set(MockCovert, MockParser):
    MockParser.logconfig = {"timestamp_key": None}
    assert isinstance(MockParser.get_timestamp(), datetime.datetime)
    MockCovert.assert_not_called()


@patch("siem.utils.convert_timestr_to_datetime")
def test_parser_get_timestamp_set_but_normalization_set(MockCovert, MockParser):
    MockParser._LogParser__skip_normalization = True
    MockParser.logconfig = {"timestamp_key": None}
    assert isinstance(MockParser.get_timestamp(), datetime.datetime)
    MockCovert.assert_not_called()


@patch("siem.utils.convert_timestr_to_datetime")
@patch("siem.utils.get_timestr_from_logdata_dict")
def test_parser_get_timestamp_bad_value(MockGet, MockCovert, MockParser):
    MockGet.return_value = "bad_timestamp"
    MockCovert.return_value = False
    MockParser._LogParser__logdata_dict = {}
    MockParser._LogParser__skip_normalization = False
    MockParser.timestamp_tz = 1
    MockParser.logconfig = {
        "timestamp_key": "bad_timestamp",
        "timestamp_format": "timestamp_format",
    }
    with pytest.raises(Exception):
        MockParser.get_timestamp()


@patch("siem.utils.convert_timestr_to_datetime")
@patch("siem.utils.get_timestr_from_logdata_dict")
def test_parser_get_timestamp_good_value(MockGet, MockCovert, MockParser):
    MockGet.return_value = "good_timestamp"
    MockCovert.return_value = "datetime"
    MockParser._LogParser__logdata_dict = {}
    MockParser._LogParser__skip_normalization = False
    MockParser.timestamp_tz = 1
    MockParser.logconfig = {
        "timestamp_key": "good_timestamp",
        "timestamp_format": "timestamp_format",
    }
    assert MockParser.get_timestamp() == "datetime"


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"a": 1, "b": {"c": 2, "d": None}}, {"a": 1, "b": {"c": 2}}),
        ({"a": 1, "b": []}, {"a": 1}),
        ({"a": 1, "b": ""}, {"a": 1}),
        ({"a": 1, "b": "-"}, {"a": 1}),
        ({"a": 1, "b": "null"}, {"a": 1}),
        ({"a": 1, "b": "[]"}, {"a": 1}),
        ({"a": 1, "b": None}, {"a": 1}),
    ],
)
def test_parser_del_none(value, expected, MockParser):
    assert MockParser.del_none(value) == expected


def test_parser_truncate_big_field_too_small(MockParser):
    data = {"foo": "bar"}
    result = MockParser.truncate_big_field(data)
    assert result == {"foo": "bar"}


def test_parser_truncate_big_field_nested(MockParser):
    data = {"foo": {"bar": "bazz"}}
    result = MockParser.truncate_big_field(data)
    assert result == {"foo": {"bar": "bazz"}}


def test_parser_truncate_big_field_but_message(MockParser):
    data = {"@message": "x" * 32766}
    result = MockParser.truncate_big_field(data)
    assert result == {"@message": "x" * 32766}


def test_parser_truncate_big_field_not_a_message(MockParser):
    data = {"@foo": "x" * 32766}
    MockParser._LogParser__logdata_dict = {"@id": "@id"}
    MockParser.logconfig = {"doc_id_suffix": None}
    result = MockParser.truncate_big_field(data)
    assert result == {"@foo": "x" * 32753 + "<<TRUNCATED>>"}
