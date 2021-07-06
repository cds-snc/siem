from siem import sf_cloudfront_standard


def test_transform():
    data = {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "http": {},
        "url": {"path": "abcd"},
        "user_agent": {"original": "El%20Ni%C3%B1o"},
    }
    result = sf_cloudfront_standard.transform(data)
    assert result == {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "distribution_id": "AAAAAAAAAAAAAA",
        "http": {"version": "2.0"},
        "url": {
            "full": "https://d111111abcdef8.cloudfront.net/images/cat.jpg?mobile=true",
            "path": "abcd",
        },
        "user_agent": {"original": "El Niño"},
    }


def test_transform_no_cs_uri_query():
    data = {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_uri_query": "-",
        "cs_uri_stem": "/images/cat.jpg?mobile=true",
        "http": {},
        "url": {"path": "abcd"},
        "user_agent": {"original": "El%20Ni%C3%B1o"},
    }
    result = sf_cloudfront_standard.transform(data)
    assert result == {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "cs_uri_query": "-",
        "cs_uri_stem": "/images/cat.jpg?mobile=true",
        "distribution_id": "AAAAAAAAAAAAAA",
        "http": {"version": "2.0"},
        "url": {
            "full": "https://d111111abcdef8.cloudfront.net/images/cat.jpg?mobile=true",
            "path": "abcd",
        },
        "user_agent": {"original": "El Niño"},
    }


def test_transform_no_ua():
    data = {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "http": {},
        "url": {"path": "abcd"},
    }
    result = sf_cloudfront_standard.transform(data)
    assert result == {
        "@log_s3key": "cloudfront/AAAAAAAAAAAAAA.2021-03-23-11.bbe0da9c.gz",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "distribution_id": "AAAAAAAAAAAAAA",
        "http": {"version": "2.0"},
        "url": {
            "full": "https://d111111abcdef8.cloudfront.net/images/cat.jpg?mobile=true",
            "path": "abcd",
        },
    }


def test_transform_no_s3key():
    data = {
        "@log_s3key": "",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "http": {},
        "url": {"path": "abcd"},
    }
    result = sf_cloudfront_standard.transform(data)
    assert result == {
        "@log_s3key": "",
        "x_host_header": "d111111abcdef8.cloudfront.net",
        "cs_protocol": "https",
        "cs_protocol_version": "HTTP/2.0",
        "cs_uri_query": "mobile=true",
        "cs_uri_stem": "/images/cat.jpg",
        "distribution_id": "unknown",
        "http": {"version": "2.0"},
        "url": {
            "full": "https://d111111abcdef8.cloudfront.net/images/cat.jpg?mobile=true",
            "path": "abcd",
        },
    }
