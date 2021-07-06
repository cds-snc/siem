from siem import sf_alb


def test_transform():
    data = {"url": {}, "request": "GET https://www.example.com:443/ HTTP/1.1"}
    result = sf_alb.transform(data)
    assert result == {
        "url": {"full": "https://www.example.com:443/"},
        "request": "GET https://www.example.com:443/ HTTP/1.1",
    }
