"""
Lambda function that downloads the MaxMind GeoDB into S3
"""

# pylint: disable=C0116, W0703, W1203

import os
import tarfile

import boto3
import logzero
import requests

logzero.json()
logger = logzero.logger

FILES = ["GeoLite2-ASN", "GeoLite2-City", "GeoLite2-Country"]
MAXMIND_KEY = os.environ.get("MAXMIND_KEY")
S3_DESTINATION = os.environ.get("S3_DESTINATION")


def handler(_event, _context):

    if MAXMIND_KEY is None:
        logger.error("MAXMIND_KEY is missing")
        return False

    if S3_DESTINATION is None:
        logger.error("S3_DESTINATION is missing")
        return False

    try:
        for file in FILES:
            return download_file(file) and store_file(file)
    except Exception as exception:
        logger.error(f"{exception}")

    return False


def download_file(file):
    url = "https://download.maxmind.com/app/geoip_download"

    params = {
        "edition_id": file,
        "license_key": MAXMIND_KEY,
        "suffix": "tar.gz",
    }

    resp = requests.get(url, params)

    if resp.status_code != 200:
        raise Exception(f"ERROR: http status {resp.status_code}")

    with open(f"/tmp/{file}.tgz", "wb") as open_file:
        open_file.write(resp.content)

    logger.debug(f"Downloaded {file}")
    return True


def store_file(file):
    with tarfile.open(f"/tmp/{file}.tgz", "r:gz") as tar_file:
        dir_name = tar_file.getmembers()[0].name
        tar_file.extractall(path="/tmp/")
        mmdb = f"{dir_name}/{file}.mmdb"

        client = get_boto3_client()
        client.upload_file(f"/tmp/{mmdb}", S3_DESTINATION, f"GeoLite2/{file}.mmdb")

    logger.debug(f"Stored {file}")
    return True


def get_boto3_client():
    return boto3.client("s3", region_name="ca-central-1")


if __name__ == "__main__":
    handler("", "")
