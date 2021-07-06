from siem import sf_msk
from unittest.mock import patch


@patch("siem.sf_msk.utils")
def test_transform_mysql_object(MockUtils):
    MockUtils.convert_underscore_field_into_dot_notation.side_effect = lambda _x, y: y
    data = {
        "@log_s3key": "/1-12345678-1234-1234-1234-123456789012-1/foo/Broker-1_",
        "msk_message": "ConsumerLag for groupId=amazon.msk.canary.group.broker-2 topic=canary : SumLag=3 MaxLag=1 TimeLag=60 (xxxxxxxxxxxx)",
    }
    result = sf_msk.transform(data)
    assert result == {
        "@log_s3key": "/1-12345678-1234-1234-1234-123456789012-1/foo/Broker-1_",
        "msk_cluster_name": "1",
        "msk_broker_id": "1",
        "msk_group_id": "amazon.msk.canary.group.broker-2",
        "msk_log_type": "ConsumerLag",
        "msk_max_lag": "1",
        "msk_message": "ConsumerLag for groupId=amazon.msk.canary.group.broker-2 "
        "topic=canary : SumLag=3 MaxLag=1 TimeLag=60 (xxxxxxxxxxxx)",
        "msk_sum_lag": "3",
        "msk_time_lag": "60",
        "msk_topic": "canary",
    }
