from siem import sf_clb


def test_transform():
    data = {"url": {}, "request": "GET https://www.example.com:443/ HTTP/1.1"}
    result = sf_clb.transform(data)
    assert result == {
        "url": {"full": "https://www.example.com:443/"},
        "request": "GET https://www.example.com:443/ HTTP/1.1",
    }


def test_transform_key_error():
    data = {"url": {}}
    result = sf_clb.transform(data)
    assert result == data
