from siem import sf_route53resolver


def test_transform():
    data = {"dns": {"question": {"name": "foo."}, "answers": {"data": "bar."}}}
    result = sf_route53resolver.transform(data)
    assert result == {"dns": {"question": {"name": "foo"}, "answers": {"data": "bar"}}}


def test_transform_missing_keys():
    data = {"foo": "bar"}
    result = sf_route53resolver.transform(data)
    assert result == {"foo": "bar"}
