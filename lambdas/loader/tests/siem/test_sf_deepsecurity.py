from siem import sf_deepsecurity


def test_transform_message_too_long():
    data = {"message": "1|2|3|4|5|6|7"}
    result = sf_deepsecurity.transform(data)
    assert result == None


def test_transform_message_no_matches():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "foo": "bar",
    }


def test_transform_message_act_match():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|cn1=1 cn1Label=Host ID dvchost=hostname cn2=205 cn2Label=Quarantine File Size cs6=ContainerImageName | ContainerName | ContainerID cs6Label=Container filePath=C:\\Users\\trend\\Desktop\\eicar.exe act=Delete result=Delete msg=Realtime TrendMicroDsMalwareTarget=N/A TrendMicroDsMalwareTargetType=N/TrendMicroDsFileMD5=44D88612FEA8A8F36DE82E1278ABB02F TrendMicroDsFileSHA1=3395856CE81F2B7382DEE72602F798B642F14140 TrendMicroDsFileSHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F TrendMicroDsDetectionConfidence=95 TrendMicroDsRelevantDetectionNames=Ransom_CERBER.BZC;Ransom_CERBER.C;Ransom_CRYPNISCA.SM",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|cn1=1 cn1Label=Host ID dvchost=hostname cn2=205 cn2Label=Quarantine File Size cs6=ContainerImageName | ContainerName | ContainerID cs6Label=Container filePath=C:\\Users\\trend\\Desktop\\eicar.exe act=Delete result=Delete msg=Realtime TrendMicroDsMalwareTarget=N/A TrendMicroDsMalwareTargetType=N/TrendMicroDsFileMD5=44D88612FEA8A8F36DE82E1278ABB02F TrendMicroDsFileSHA1=3395856CE81F2B7382DEE72602F798B642F14140 TrendMicroDsFileSHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F TrendMicroDsDetectionConfidence=95 TrendMicroDsRelevantDetectionNames=Ransom_CERBER.BZC;Ransom_CERBER.C;Ransom_CRYPNISCA.SM",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "cn1Label": "Host ID",
        "dvchost": "hostname",
        "cn2": "205",
        "cn2Label": "Quarantine File Size",
        "cs6": "ContainerImageName",
        "host": {"id": "1"},
    }


def test_transform_message_dvc_match():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|cn1=1 cn1Label=Host ID dvchost=hostname dvc=127.0.0.1 cn2=205 cn2Label=Quarantine File Size cs6=ContainerImageName | ContainerName | ContainerID cs6Label=Container filePath=C:\\Users\\trend\\Desktop\\eicar.exe act=Delete result=Delete msg=Realtime TrendMicroDsMalwareTarget=N/A TrendMicroDsMalwareTargetType=N/TrendMicroDsFileMD5=44D88612FEA8A8F36DE82E1278ABB02F TrendMicroDsFileSHA1=3395856CE81F2B7382DEE72602F798B642F14140 TrendMicroDsFileSHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F TrendMicroDsDetectionConfidence=95 TrendMicroDsRelevantDetectionNames=Ransom_CERBER.BZC;Ransom_CERBER.C;Ransom_CRYPNISCA.SM",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|cn1=1 cn1Label=Host ID dvchost=hostname dvc=127.0.0.1 cn2=205 cn2Label=Quarantine File Size cs6=ContainerImageName | ContainerName | ContainerID cs6Label=Container filePath=C:\\Users\\trend\\Desktop\\eicar.exe act=Delete result=Delete msg=Realtime TrendMicroDsMalwareTarget=N/A TrendMicroDsMalwareTargetType=N/TrendMicroDsFileMD5=44D88612FEA8A8F36DE82E1278ABB02F TrendMicroDsFileSHA1=3395856CE81F2B7382DEE72602F798B642F14140 TrendMicroDsFileSHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F TrendMicroDsDetectionConfidence=95 TrendMicroDsRelevantDetectionNames=Ransom_CERBER.BZC;Ransom_CERBER.C;Ransom_CRYPNISCA.SM",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "cn1Label": "Host ID",
        "dvchost": "hostname",
        "dvc": "127.0.0.1",
        "cn2": "205",
        "cn2Label": "Quarantine File Size",
        "cs6": "ContainerImageName",
        "host": {"id": "1"},
        "source": {"ip": "127.0.0.1"},
    }


def test_transform_ds_packet_bad_encode():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
        "TrendMicroDsPacketData": "z",
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "foo": "bar",
        "TrendMicroDsPacketData": "z",
    }


def test_transform_ds_packet_filter_cookie():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
        "TrendMicroDsPacketData": "Zm9vCmNvb2tpZQpiYXI=",
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "foo": "bar",
        "TrendMicroDsPacketData": "foo\nbar",
    }


def test_transform_ds_packet_find_ip():
    data = {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "TrendMicroDsTenant": "foo",
        "TrendMicroDsTenantId": "bar",
        "TrendMicroDsPacketData": "WC1Gb3J3YXJkZWQtRm9yOiAxMjMuMTIzLjEyMy4yMzQ=",
        "source": {},
    }
    result = sf_deepsecurity.transform(data)
    assert result == {
        "message": "CEF:0|Trend Micro|Deep Security Agent|<DSA version>|4000000|Eicar_test_file|6|foo=bar",
        "agent": {"name": "Trend Micro Deep Security Agent <DSA version>"},
        "rule": {"name": "4000000 Eicar_test_file"},
        "event": {"severity": "6"},
        "foo": "bar",
        "TrendMicroDsPacketData": "X-Forwarded-For: 123.123.123.234",
        "source": {"ip": "123.123.123.234"},
    }
