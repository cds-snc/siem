from siem import sf_cloudtrail


def test_convert_text_into_dict():
    assert sf_cloudtrail.convert_text_into_dict("foo") == {"value": "foo"}
    assert sf_cloudtrail.convert_text_into_dict(6) == 6


def test_transform_outcome_failure():
    data = {"errorCode": "foo", "event": {}}
    result = sf_cloudtrail.transform(data)
    assert result == {"errorCode": "foo", "event": {"outcome": "failure"}}

    data = {"errorMessage": "foo", "event": {}}
    result = sf_cloudtrail.transform(data)
    assert result == {"errorMessage": "foo", "event": {"outcome": "failure"}}


def test_transform_outcome_success():
    data = {"event": {}}
    result = sf_cloudtrail.transform(data)
    assert result == {"event": {"outcome": "success"}}


def test_transform_user_name():
    data = {"event": {}, "user": {"name": "foo:bar/baz"}}
    result = sf_cloudtrail.transform(data)
    assert result == {"event": {"outcome": "success"}, "user": {"name": "baz"}}


def test_transform_credentials_not_string():
    data = {"event": {}, "responseElements": {"credentials": 6}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "responseElements": {"credentials": 6},
    }


def test_transform_credentials_iam():
    data = {"event": {}, "responseElements": {"credentials": "arn:aws:iam:foo:bar"}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "responseElements": {"credentials": {"iam": "arn:aws:iam:foo:bar"}},
    }


def test_transform_credentials_value():
    data = {"event": {}, "responseElements": {"credentials": "foo:bar"}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "responseElements": {"credentials": {"value": "foo:bar"}},
    }


def test_transform_tags_str():
    data = {"event": {}, "requestParameters": {"tags": "foo"}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "requestParameters": {"tags": {"value": "foo"}},
    }


def test_transform_tags_not_str():
    data = {"event": {}, "requestParameters": {"tags": 6}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "requestParameters": {"tags": 6},
    }


def test_transform_policy_str():
    data = {"event": {}, "responseElements": {"policy": "foo"}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "responseElements": {"policy": {"value": "foo"}},
    }


def test_transform_policy_not_str():
    data = {"event": {}, "responseElements": {"policy": 6}}
    result = sf_cloudtrail.transform(data)
    assert result == {
        "event": {"outcome": "success"},
        "responseElements": {"policy": 6},
    }
