import datetime
import pytest
import os

from siem import geodb
from unittest.mock import MagicMock, patch


@pytest.fixture(scope="session", autouse=True)
def geoip2_mock():
    with patch.object(geodb, "geoip2") as _fixture:
        yield _fixture


def test_geodb_init():
    db = geodb.GeoDB()
    assert db._reader_city is None
    assert db._reader_asn is None


@patch("siem.geodb.GeoDB._get_geoip_buckent_name")
@patch("siem.geodb.GeoDB._download_geoip_database")
def test_geodb_init_with_data(MockDownload, MockBucketName):
    MockDownload.return_value = "foo"
    MockBucketName.return_value = "foo"
    db = geodb.GeoDB()
    assert db._reader_city is not None
    assert db._reader_asn is not None


@patch("siem.geodb.GeoDB._get_geo_city")
@patch("siem.geodb.GeoDB._get_geo_asn")
def test_check_ipaddress(MockAsn, MockCity):
    MockCity.return_value = "city"
    MockAsn.return_value = "asn"
    db = geodb.GeoDB()
    assert db.check_ipaddress(None) == (None, None)
    assert db.check_ipaddress("") == (None, None)
    assert db.check_ipaddress("127.0.0.1") == ("city", "asn")


@patch.dict(os.environ, {"GEOIP_BUCKET": "foo"}, clear=True)
def test_get_geoip_buckent_name_with_os_var():
    db = geodb.GeoDB()
    assert db._get_geoip_buckent_name() == "foo"


@patch("siem.geodb.configparser")
def test_get_geoip_buckent_name_config(MockConfigParser):
    result = MagicMock()
    result.__contains__.return_value = True
    result.__getitem__.return_value = {"GEOIP_BUCKET": "foo"}
    MockConfigParser.ConfigParser.return_value = result
    db = geodb.GeoDB()
    assert db._get_geoip_buckent_name() == "foo"


@patch("siem.geodb.os")
def test_delete_file_older_than_seconds_younger(MockOs):
    MockFile = MagicMock(st_ctime=(datetime.datetime.now().timestamp() - 999))
    MockOs.stat.return_value = MockFile
    db = geodb.GeoDB()
    assert db._delete_file_older_than_seconds("foo", 1000) == False
    MockOs.remove.assert_not_called()


@patch("siem.geodb.os")
def test_delete_file_older_than_seconds_older(MockOs):
    MockFile = MagicMock(st_ctime=(datetime.datetime.now().timestamp() - 1000))
    MockOs.stat.return_value = MockFile
    db = geodb.GeoDB()
    assert db._delete_file_older_than_seconds("foo", 999) == True
    MockOs.remove.assert_called_once()


@patch("siem.geodb.GeoDB._delete_file_older_than_seconds")
@patch("siem.geodb.os")
def test_download_geoip_database_local_file_not_found_delete_error(MockOs, MockDelete):
    MockOs.path.isfile.return_value = True
    MockDelete.return_value = False
    db = geodb.GeoDB()
    assert db._download_geoip_database("foo", "bar") == False


@patch("siem.geodb.GeoDB._delete_file_older_than_seconds")
@patch("siem.geodb.os")
def test_download_geoip_database_local_file_delete_error(MockOs, MockDelete):
    MockOs.path.isfile.side_effect = [False, True]
    MockDelete.return_value = False
    db = geodb.GeoDB()
    assert db._download_geoip_database("foo", "bar") == True


@patch("siem.geodb.os")
@patch("siem.geodb.boto3")
def test_download_geoip_database_local_file_download_success(MockBoto, MockOs):
    MockOs.path.isfile.side_effect = [False, False, False]
    db = geodb.GeoDB()
    assert db._download_geoip_database("foo", "bar") == True
    MockBoto.resource.Bucket.download_file.assert_called_once


@patch("siem.geodb.os")
@patch("siem.geodb.boto3")
def test_download_geoip_database_local_file_download_failure(MockBoto, MockOs):
    MockOs.path.isfile.side_effect = [False, False, False]
    db = geodb.GeoDB()
    MockBoto.resource.Bucket.download_file.side_effect = Exception("Boom!")
    assert db._download_geoip_database("foo", "bar") == True
    MockBoto.resource.Bucket.download_file.assert_called_once


def test_get_geo_city_not_set():
    db = geodb.GeoDB()
    assert db._get_geo_city("127.0.0.1") == None


def test_get_geo_city_exception():
    MockCity = MagicMock()
    MockCity.city.side_effect = Exception("Boom!")
    db = geodb.GeoDB()
    db._reader_city = MockCity
    assert db._get_geo_city("127.0.0.1") == None


def test_get_geo_city_full_data():
    MockCity = MagicMock()
    MockCity.city().city.name = "Foo"
    MockCity.city().country.iso_code = "FO"
    MockCity.city().country.name = "OO"
    MockCity.city().location.longitude = "12"
    MockCity.city().location.latitude = "34"
    db = geodb.GeoDB()
    db._reader_city = MockCity
    assert db._get_geo_city("127.0.0.1") == {
        "city_name": "Foo",
        "country_iso_code": "FO",
        "country_name": "OO",
        "location": {"lon": "12", "lat": "34"},
    }


def test_get_geo_asn_not_set():
    db = geodb.GeoDB()
    assert db._get_geo_asn("127.0.0.1") == None


def test_get_geo_asn_exception():
    MockAsn = MagicMock()
    MockAsn.asn.side_effect = Exception("Boom!")
    db = geodb.GeoDB()
    db._reader_asn = MockAsn
    assert db._get_geo_asn("127.0.0.1") == None


def test_get_geo_asn_full_data():
    MockAsn = MagicMock()
    MockAsn.asn().autonomous_system_number = "Foo"
    MockAsn.asn().autonomous_system_organization = "Bar"
    db = geodb.GeoDB()
    db._reader_asn = MockAsn
    assert db._get_geo_asn("127.0.0.1") == {
        "number": "Foo",
        "organization": {"name": "Bar"},
    }
