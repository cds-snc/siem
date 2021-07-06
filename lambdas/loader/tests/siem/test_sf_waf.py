from siem import sf_waf


def test_transform_headers():
    data = {
        "http": {"request": {}},
        "httpRequest": {
            "headers": [
                {"name": "Host", "value": "foo.bar"},
                {"name": "User-Agent", "value": "foozilla"},
                {"name": "Referer", "value": "foo.baz"},
            ],
            "httpVersion": "HTTP/2",
        },
        "rule": {},
        "url": {},
        "webaclId": "foo",
    }
    result = sf_waf.transform(data)
    assert result == {
        "http": {"request": {"referrer": "foo.baz"}, "version": "2"},
        "httpRequest": {
            "headers": [
                {"name": "Host", "value": "foo.bar"},
                {"name": "User-Agent", "value": "foozilla"},
                {"name": "Referer", "value": "foo.baz"},
            ],
            "httpVersion": "HTTP/2",
        },
        "rule": {"ruleset": "foo"},
        "url": {"domain": "foo.bar"},
        "user_agent": {"original": "foozilla"},
        "webaclId": "foo",
    }


def test_transform_waf_v2_regional():
    data = {
        "cloud": {},
        "http": {"request": {}},
        "httpRequest": {"headers": [], "httpVersion": "HTTP/2"},
        "rule": {},
        "url": {},
        "webaclId": "arn:aws:wafv2:ca-central-1:000000000000:regional/webacl/name/00000000-0000-0000-0000-000000000000",
    }
    result = sf_waf.transform(data)
    assert result == {
        "cloud": {"account": {"id": "000000000000"}, "region": "ca-central-1"},
        "http": {"request": {}, "version": "2"},
        "httpRequest": {
            "headers": [],
            "httpVersion": "HTTP/2",
        },
        "rule": {"ruleset": "name"},
        "url": {},
        "webaclId": "arn:aws:wafv2:ca-central-1:000000000000:regional/webacl/name/00000000-0000-0000-0000-000000000000",
    }


def test_transform_waf_v2_global():
    data = {
        "cloud": {},
        "http": {"request": {}},
        "httpRequest": {"headers": [], "httpVersion": "HTTP/2"},
        "rule": {},
        "url": {},
        "webaclId": "arn:aws:wafv2:ca-central-1:000000000000:global/webacl/name/00000000-0000-0000-0000-000000000000",
    }
    result = sf_waf.transform(data)
    assert result == {
        "cloud": {"account": {"id": "000000000000"}, "region": "global"},
        "http": {"request": {}, "version": "2"},
        "httpRequest": {
            "headers": [],
            "httpVersion": "HTTP/2",
        },
        "rule": {"ruleset": "name"},
        "url": {},
        "webaclId": "arn:aws:wafv2:ca-central-1:000000000000:global/webacl/name/00000000-0000-0000-0000-000000000000",
    }
