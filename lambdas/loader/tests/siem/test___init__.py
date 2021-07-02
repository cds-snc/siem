import io
import re
import pytest

from siem import LogS3

from unittest.mock import MagicMock, patch


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
def test_init(MockExtractMessage, MockExtractRawHeader, MockExtractRaw):
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


def test_iter_ignored(MockLog):
    MockLog.is_ignored = True
    a = [x for x in MockLog]
    assert a == []


@patch("siem.LogS3.logdata_generator")
def test_iter_low_log_count(MockGenerator, MockLog):
    MockLog.log_count = 0
    MockLog.max_log_count = 1
    MockGenerator.return_value = [1, 2, 3]
    a = [x for x in MockLog]
    assert a == [1, 2, 3]


@patch("siem.LogS3.logdata_generator")
def test_iter_no_sqs(MockGenerator, MockLog):
    MockLog.log_count = 1
    MockLog.max_log_count = 0
    MockLog.sqs_queue = None
    MockGenerator.return_value = [1, 2, 3]
    a = [x for x in MockLog]
    assert a == [1, 2, 3]


@patch("siem.LogS3.split_logs")
@patch("siem.LogS3.send_meta_to_sqs")
def test_iter_split(MockSendMeta, MockSplitLogs, MockLog):
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


def test_is_ignored_bad_key(MockLog):
    MockLog.s3key = "/"
    assert LogS3.is_ignored.func(MockLog) == True
    assert MockLog.ignored_reason == f"this s3 key is just path, /"


def test_is_ignored_unkown_logtype(MockLog):
    MockLog.logtype = "unknown"
    assert LogS3.is_ignored.func(MockLog) == True
    assert MockLog.ignored_reason == f"unknown log type in S3 key, bar"


def test_is_ignored_ignored_key_match(MockLog):
    MockLog.logconfig["s3_key_ignored"] = re.compile("^bar$")
    assert LogS3.is_ignored.func(MockLog) == True
    assert (
        MockLog.ignored_reason
        == f"\"s3_key_ignored\" re.compile('^bar$') matched with bar"
    )


def test_is_ignored_ignored_no_key_match(MockLog):
    MockLog.logconfig["s3_key_ignored"] = re.compile("^foo$")
    assert LogS3.is_ignored.func(MockLog) == False


def test_log_count_end_not_0(MockLog):
    MockLog.end_number = 3
    MockLog.start_number = 2
    assert LogS3.log_count.func(MockLog) == 1


def test_log_count_no_logs(MockLog):
    MockLog.end_number = 0
    MockLog.file_format = ""
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 0
    MockLog.is_ignored = True
    MockLog.ignored_reason = "there are not any valid logs in S3 object"


@patch("siem.LogS3.rawdata")
def test_log_count_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = "csv"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.rawdata")
def test_log_count_text(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = "text"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.rawdata")
def test_log_count_firelens(MockRawData, MockLog):
    MockRawData.readlines.return_value = [1, 2]
    MockLog.end_number = 0
    MockLog.file_format = ""
    MockLog.via_firelens = "via_firelens"
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.extract_logobj_from_json")
def test_log_count_json(MockLogObj, MockLog):
    MockLogObj.return_value = [2]
    MockLog.end_number = 0
    MockLog.file_format = "json"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


@patch("siem.LogS3.count_multiline_log")
def test_log_count_multiline(MockCountMultiLine, MockLog):
    MockCountMultiLine.return_value = 2
    MockLog.end_number = 0
    MockLog.file_format = "multiline"
    MockLog.via_firelens = None
    assert LogS3.log_count.func(MockLog) == 2


def test_rawdata(MockLog):
    data = MagicMock()
    MockLog._LogS3__rawdata = data
    assert MockLog.rawdata == data


@patch("siem.LogS3.rawdata")
def test_csv_header_with_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = ["foo", "bar"]
    MockLog.file_format = "csv"
    assert LogS3.csv_header.func(MockLog) == "foo"


def test_csv_header_no_csv(MockLog):
    MockLog.file_format = ""
    assert LogS3.csv_header.func(MockLog) == None


@patch("siem.utils.extract_aws_account_from_text")
def test_accountid_failed_extract(MockExtract, MockLog):
    MockExtract.return_value = False
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == None


@patch("siem.utils.extract_aws_account_from_text")
def test_accountid_extract(MockExtract, MockLog):
    MockExtract.return_value = "foo"
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == "foo"


def test_accountid_cwl_accountid(MockLog):
    MockLog.cwl_accountid = "foo"
    MockLog.cwe_accountid = None
    assert LogS3.accountid.func(MockLog) == "foo"


def test_accountid_cwe_accountid(MockLog):
    MockLog.cwl_accountid = None
    MockLog.cwe_accountid = "foo"
    assert LogS3.accountid.func(MockLog) == "foo"


@patch("siem.utils.extract_aws_region_from_text")
def test_region_failed_extract(MockExtract, MockLog):
    MockExtract.return_value = False
    MockLog.cwe_region = None
    assert LogS3.region.func(MockLog) == None


@patch("siem.utils.extract_aws_region_from_text")
def test_region_extract(MockExtract, MockLog):
    MockExtract.return_value = "foo"
    MockLog.cwe_region = None
    assert LogS3.region.func(MockLog) == "foo"


def test_region_cwe_region(MockLog):
    MockLog.cwe_region = "foo"
    assert LogS3.region.func(MockLog) == "foo"


def test_start_number(MockLog):
    MockLog.record = {"siem": {"start_number": 1}}
    assert LogS3.start_number.func(MockLog) == 1


def test_start_number_error(MockLog):
    MockLog.record = {"siem": {}}
    assert LogS3.start_number.func(MockLog) == 0


def test_end_number(MockLog):
    MockLog.record = {"siem": {"end_number": 1}}
    assert LogS3.end_number.func(MockLog) == 1


def test_end_number_error(MockLog):
    MockLog.record = {"siem": {}}
    assert LogS3.end_number.func(MockLog) == 0


def test_startmsg(MockLog):
    assert MockLog.startmsg() == {
        "end_number": 0,
        "logtype": "",
        "msg": "Invoked es-loader",
        "s3_bucket": "foo",
        "s3_key": "bar",
        "start_number": 0,
    }


@patch("siem.LogS3.rawdata")
def test_logdata_generator_text(MockRawData, MockLog):
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
def test_logdata_generator_csv(MockRawData, MockLog):
    MockRawData.readlines.return_value = ["foo", "bar"]

    MockLog.file_format = "csv"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 2

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["bar"]
    assert MockLog.total_log_count == 1


@patch("siem.LogS3.extract_logobj_from_json")
def test_logdata_generator_json(MockExtract, MockLog):
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
def test_logdata_generator_multiline(MockExtract, MockLog):
    MockExtract.return_value = ["foo", "bar"]

    MockLog.via_firelens = None
    MockLog.file_format = "multiline"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 3

    a = [x for x in MockLog.logdata_generator()]
    assert a == ["foo", "bar"]
    assert MockLog.total_log_count == 2


def test_logdata_generator_exception(MockLog):
    MockLog.via_firelens = None
    MockLog.file_format = "foo"

    MockLog.start_number = 0
    MockLog.log_count = 2
    MockLog.max_log_count = 3

    with pytest.raises(Exception):
        [x for x in MockLog.logdata_generator()]


def test_extract_header_from_cwl_empty(MockLog):
    data = MagicMock()
    data.read.return_value = ""
    assert MockLog.extract_header_from_cwl(data) == (None, None, None)


@patch("siem.json")
def test_extract_header_from_cwl(MockJson, MockLog):
    data = MagicMock()
    MockJson.JSONDecoder().raw_decode.side_effect = [
        ({"messageType": "CONTROL_MESSAGE"}, 1),
        ({"messageType": "", "logGroup": "foo", "logStream": "bar", "owner": "baz"}, 2),
    ]
    assert MockLog.extract_header_from_cwl(data) == ("foo", "bar", "baz")


@patch("siem.json")
def test_extract_messages_from_cwl(MockJson, MockLog):
    data = MagicMock()
    data.read.return_value = "11"
    MockJson.JSONDecoder().raw_decode.side_effect = [
        ({"messageType": "CONTROL_MESSAGE"}, 1),
        ({"messageType": "", "logEvents": [{"message": "foo"}]}, 2),
    ]
    result = MockLog.extract_messages_from_cwl(data)
    assert result.read() == "foo\n"


def test_extract_rawdata_from_s3obj_exception(MockLog):
    MockLog.s3key = "foo"
    MockLog.s3_client = MagicMock()
    MockLog.s3_client.get_object.return_value = Exception("Boom!")
    with pytest.raises(Exception):
        MockLog.extract_rawdata_from_s3obj()


def test_extract_rawdata_from_s3obj_size_too_small(MockLog):
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"ResponseMetadata": {"HTTPHeaders": {"content-length": 0}}}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == None
    MockLog.s3_client.get_object.assert_called_once_with(Bucket="foo", Key="bar")
    assert MockLog.is_ignored == True


@patch("siem.utils.get_mime_type")
def test_extract_rawdata_from_s3obj_mime_exception(MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "unkown"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    with pytest.raises(Exception):
        MockLog.extract_rawdata_from_s3obj()


@patch("siem.utils.get_mime_type")
@patch("siem.gzip")
def test_extract_rawdata_from_s3obj_gzip(MockGZip, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "gzip"
    MockGZip.open.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.utils.get_mime_type")
@patch("siem.io.TextIOWrapper")
def test_extract_rawdata_from_s3obj_text(MockText, MockGetMimeType, MockLog):
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
def test_extract_rawdata_from_s3obj_zip(MockOpen, _MockZip, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "zip"
    MockOpen.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.utils.get_mime_type")
@patch("siem.bz2")
def test_extract_rawdata_from_s3obj_bzip2(MockBz2, MockGetMimeType, MockLog):
    MockGetMimeType.return_value = "bzip2"
    MockBz2.open.return_value = "response"
    MockLog.s3key = "bar"
    MockLog.s3_client = MagicMock()
    responseObj = {"Body": io.BytesIO(b"binary data: \x00\x01")}
    MockLog.s3_client.get_object.return_value = responseObj
    assert MockLog.extract_rawdata_from_s3obj() == "response"


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_extract_logobj_from_json_no_delimiter_count(MockStrip, MockLog):
    MockStrip.side_effect = [{"event": 1}, {"event": 2}]
    MockLog.logconfig = {"json_delimiter": False}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json()]
    assert a == [1, 2]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_extract_logobj_from_json_delimiter_count(MockStrip, MockLog):
    MockStrip.side_effect = [
        {"|": [{"event": 1}, {"event": 2}]},
        {"|": [{"event": 3}, {"event": 4}]},
    ]
    MockLog.logconfig = {"json_delimiter": "|"}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json()]
    assert a == [2, 4]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_extract_logobj_from_json_no_delimiter_no_count(MockStrip, MockLog):
    MockStrip.side_effect = [{"event": 1}, {"event": 2}]
    MockLog.logconfig = {"json_delimiter": False}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json(mode="foo", end=2)]
    assert a == [{"event": 1}, {"event": 2}]


@patch("siem.LogS3.check_cwe_and_strip_header")
def test_extract_logobj_from_json_delimiter_no_count(MockStrip, MockLog):
    MockStrip.side_effect = [
        {"|": [{"event": 1}, {"event": 2}]},
        {"|": [{"event": 3}, {"event": 4}]},
    ]
    MockLog.logconfig = {"json_delimiter": "|"}
    MockLog.rawdata.readlines.return_value = ["{}", "{}"]
    a = [x for x in MockLog.extract_logobj_from_json(mode="foo", end=2)]
    assert a == [{"event": 1}, {"event": 2}]


def test_match_multiline_firstline_true(MockLog):
    MockLog.re_multiline_firstline = re.compile("^foo$")
    assert MockLog.match_multiline_firstline("foo") == True


def test_match_multiline_firstline_false(MockLog):
    MockLog.re_multiline_firstline = re.compile("^foo$")
    assert MockLog.match_multiline_firstline("bar") == False


@patch("siem.LogS3.match_multiline_firstline")
def test_count_multiline_log(MockMatch, MockLog):
    MockLog.rawdata.__iter__.return_value = ["foo", "bar"]
    MockMatch.side_effect = [True, False]
    assert MockLog.count_multiline_log() == 1


@patch("siem.LogS3.match_multiline_firstline")
def test_extract_multiline_log(MockMatch, MockLog):
    MockLog.rawdata.__iter__.return_value = ["foo", "bar"]
    MockMatch.side_effect = [True, False]
    a = [x for x in MockLog.extract_multiline_log(end=2)]
    assert a == ["foobar"]


def test_check_cwe_and_strip_header_no_match(MockLog):
    assert MockLog.check_cwe_and_strip_header({}) == {}


def test_check_cwe_and_strip_header(MockLog):
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
def test_split_logs(log_count, max_log_count, expected, MockLog):
    assert MockLog.split_logs(log_count, max_log_count) == expected


def test_send_meta_to_sqs_exception(MockLog):
    MockLog.sqs_queue.send_messages.return_value = {
        "ResponseMetadata": {"HTTPStatusCode": 500}
    }
    with pytest.raises(Exception):
        MockLog.send_meta_to_sqs([(1, 2)])


def test_send_meta_to_sqs(MockLog):
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
