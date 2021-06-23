from siem import sf_s3accesslog


def test_transform():
    data = {"cloud": {"region": "ca-central-1"}, "user": {"name": "foo/bar"}}
    result = sf_s3accesslog.transform(data)
    assert result == {"cloud": {"region": "ca-central-1"}, "user": {"name": "bar"}}


def test_transform_no_user():
    data = {"cloud": {"region": "ca-central-1"}}
    result = sf_s3accesslog.transform(data)
    assert result == {"cloud": {"region": "ca-central-1"}}


def test_transform_unknown_region():
    data = {
        "cloud": {"region": "unknown"},
        "user": {"name": "foo/bar"},
        "EndPoint": "ca-central-1.foo.bar",
    }
    result = sf_s3accesslog.transform(data)
    assert result == {
        "cloud": {"region": "ca-central-1"},
        "user": {"name": "bar"},
        "EndPoint": "ca-central-1.foo.bar",
    }
