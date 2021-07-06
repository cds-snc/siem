#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import os
import re
import sys
import time
from functools import lru_cache, wraps

import boto3
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.metrics import MetricUnit

import siem
from siem import geodb, utils

__version__ = "2.3.2"


logger = Logger(stream=sys.stdout, log_record_order=["level", "message"])
logger.info("version: " + __version__)
metrics = Metrics()

SQS_SPLITTED_LOGS_URL = None
if "SQS_SPLITTED_LOGS_URL" in os.environ:
    SQS_SPLITTED_LOGS_URL = os.environ["SQS_SPLITTED_LOGS_URL"]
ES_HOSTNAME = utils.get_es_hostname()


def extract_logfile_from_s3(record):
    if "s3" in record:
        s3key = record["s3"]["object"]["key"]
        logger.structure_logs(append=True, s3_key=s3key)
        logtype = utils.get_logtype_from_s3key(s3key, logtype_s3key_dict)
        logconfig = create_logconfig(logtype)
        logfile = siem.LogS3(record, logtype, logconfig, s3_client, sqs_queue)
    else:
        logger.error("invalid input data. exit")
        raise Exception("invalid input data. exit")
    return logfile


@lru_cache(maxsize=1024)
def get_value_from_etl_config(logtype, key, keytype=None):
    try:
        if keytype is None:
            value = etl_config[logtype][key]
        elif keytype == "bool":
            value = etl_config[logtype].getboolean(key)
        elif keytype == "int":
            value = etl_config[logtype].getint(key)
        elif keytype == "re":
            rawdata = etl_config[logtype][key]
            if rawdata:
                value = re.compile(rawdata)
            else:
                value = ""
        else:
            value = ""
    except KeyError:
        logger.exception("unknown error")
        raise KeyError("Can't find the key in logconfig")
    except re.error:
        logger.exception(f"invalid regex pattern for {key}")
        raise Exception(f"invalid regex pattern for {key}") from None
    except Exception:
        logger.exception("unknown error")
        raise Exception("unknown error") from None
    return value


@lru_cache(maxsize=128)
def create_logconfig(logtype):
    type_re = ["s3_key_ignored", "log_pattern", "multiline_firstline"]
    type_int = ["max_log_count", "text_header_line_number", "ignore_header_line_number"]
    type_bool = ["via_cwl", "via_firelens", "ignore_container_stderr", "timestamp_nano"]
    logconfig = {}
    if logtype in ("unknown", "nodata"):
        return logconfig
    for key in etl_config[logtype]:
        if key in type_re:
            logconfig[key] = get_value_from_etl_config(logtype, key, "re")
        elif key in type_int:
            logconfig[key] = get_value_from_etl_config(logtype, key, "int")
        elif key in type_bool:
            logconfig[key] = get_value_from_etl_config(logtype, key, "bool")
        else:
            logconfig[key] = get_value_from_etl_config(logtype, key)
    return logconfig


def get_es_entries(logfile, exclude_log_patterns):
    """get elasticsearch entries.

    To return json to load AmazonES, extract log, map fields to ecs fields and
    enrich ip addresses with geoip. Most important process.
    """
    # ETL対象のログタイプのConfigだけを限定して定義する
    logconfig = create_logconfig(logfile.logtype)
    # load custom script
    sf_module = utils.load_sf_module(logfile, logconfig, user_libs_list)

    logparser = siem.LogParser(
        logfile, logconfig, sf_module, geodb_instance, exclude_log_patterns
    )
    for logdata in logfile:
        logparser(logdata)
        if logparser.is_ignored:
            logger.debug(f"Skipped log because {logparser.ignored_reason}")
            continue
        yield {"index": {"_index": logparser.indexname, "_id": logparser.doc_id}}
        # logger.debug(logparser.json)
        yield logparser.json


def check_es_results(results):
    duration = results["took"]
    success, error = 0, 0
    error_reasons = []
    if not results["errors"]:
        success = len(results["items"])
    else:
        for result in results["items"]:
            if result["index"]["status"] >= 300:
                # status code
                # 200:OK, 201:Created, 400:NG
                error += 1
                error_reason = result["index"].get("error")
                if error_reason:
                    error_reasons.append(error_reason)
            else:
                success += 1

    return duration, success, error, error_reasons


def bulkloads_into_elasticsearch(es_entries, collected_metrics):
    output_size, total_output_size = 0, 0
    total_count, success_count, error_count, es_response_time = 0, 0, 0, 0
    results = False
    putdata_list = []
    error_reason_list = []
    filter_path = [
        "took",
        "errors",
        "items.index.status",
        "items.index.error.reason",
        "items.index.error.type",
    ]
    for data in es_entries:
        putdata_list.append(data)
        output_size += len(str(data))
        # es の http.max_content_length は t2 で10MB なのでデータがたまったらESにロード
        if isinstance(data, str) and output_size > 6000000:
            total_output_size += output_size
            results = es_conn.bulk(putdata_list, filter_path=filter_path)
            es_took, success, error, error_reasons = check_es_results(results)
            success_count += success
            error_count += error
            es_response_time += es_took
            output_size = 0
            total_count += len(putdata_list)
            putdata_list = []
            if len(error_reasons):
                error_reason_list.extend([error_reasons])
    if output_size > 0:
        total_output_size += output_size
        results = es_conn.bulk(putdata_list, filter_path=filter_path)
        # logger.debug(results)
        es_took, success, error, error_reasons = check_es_results(results)
        success_count += success
        error_count += error
        es_response_time += es_took
        total_count += len(putdata_list)
        if len(error_reasons):
            error_reason_list.extend([error_reasons])
    collected_metrics["total_output_size"] = total_output_size
    collected_metrics["total_log_load_count"] = total_count
    collected_metrics["success_count"] = success_count
    collected_metrics["error_count"] = error_count
    collected_metrics["es_response_time"] = es_response_time

    return collected_metrics, error_reason_list


def output_metrics(metrics, record=None, logfile=None, collected_metrics={}):
    if not os.environ.get("AWS_EXECUTION_ENV"):
        return
    total_output_size = collected_metrics["total_output_size"]
    success_count = collected_metrics["success_count"]
    error_count = collected_metrics["error_count"]
    es_response_time = collected_metrics["es_response_time"]
    input_file_size = record["s3"]["object"].get("size", 0)
    s3_key = record["s3"]["object"]["key"]
    duration = int((time.perf_counter() - collected_metrics["start_time"]) * 1000) + 10
    total_log_count = logfile.total_log_count

    metrics.add_dimension(name="logtype", value=logfile.logtype)
    metrics.add_metric(
        name="InputLogFileSize", unit=MetricUnit.Bytes, value=input_file_size
    )
    metrics.add_metric(
        name="OutputDataSize", unit=MetricUnit.Bytes, value=total_output_size
    )
    metrics.add_metric(
        name="SuccessLogLoadCount", unit=MetricUnit.Count, value=success_count
    )
    metrics.add_metric(
        name="ErrorLogLoadCount", unit=MetricUnit.Count, value=error_count
    )
    metrics.add_metric(
        name="TotalDurationTime", unit=MetricUnit.Milliseconds, value=duration
    )
    metrics.add_metric(
        name="EsResponseTime", unit=MetricUnit.Milliseconds, value=es_response_time
    )
    metrics.add_metric(name="TotalLogFileCount", unit=MetricUnit.Count, value=1)
    metrics.add_metric(
        name="TotalLogCount", unit=MetricUnit.Count, value=total_log_count
    )
    metrics.add_metadata(key="s3_key", value=s3_key)


def observability_decorator_switcher(func):
    if os.environ.get("AWS_EXECUTION_ENV"):

        @metrics.log_metrics
        @logger.inject_lambda_context
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)

        return decorator
    else:
        # local environment
        @wraps(func)
        def decorator(*args, **kwargs):
            return func(*args, **kwargs)

        return decorator


es_conn = utils.initialize_es_connection(ES_HOSTNAME)
user_libs_list = utils.find_user_custom_libs()
etl_config = utils.get_etl_config()
utils.load_modules_on_memory(etl_config, user_libs_list)
logtype_s3key_dict = utils.create_logtype_s3key_dict(etl_config)

exclude_own_log_patterns = utils.make_exclude_own_log_patterns(etl_config)
csv_filename = utils.get_exclude_log_patterns_csv_filename(etl_config)
exclude_log_patterns = utils.merge_csv_into_log_patterns(
    exclude_own_log_patterns, csv_filename
)
s3_session_config = utils.make_s3_session_config(etl_config)
s3_client = boto3.client("s3", config=s3_session_config)
sqs_queue = utils.sqs_queue(SQS_SPLITTED_LOGS_URL)

geodb_instance = geodb.GeoDB()
utils.show_local_dir()


@observability_decorator_switcher
def lambda_handler(event, context):
    for record in event["Records"]:
        collected_metrics = {"start_time": time.perf_counter()}
        if "body" in record:
            # from sqs-splitted-logs
            record = json.loads(record["body"])
        # S3からファイルを取得してログを抽出する
        logfile = extract_logfile_from_s3(record)
        if logfile.is_ignored:
            logger.warning(f"Skipped S3 object because {logfile.ignored_reason}")
            continue

        # 抽出したログからESにPUTするデータを作成する
        es_entries = get_es_entries(logfile, exclude_log_patterns)
        # 作成したデータをESにPUTしてメトリクスを収集する
        collected_metrics, error_reason_list = bulkloads_into_elasticsearch(
            es_entries, collected_metrics
        )
        output_metrics(
            metrics, record=record, logfile=logfile, collected_metrics=collected_metrics
        )
        # raise error to retry if error has occuered
        if logfile.is_ignored:
            logger.warning(f"Skipped S3 object because {logfile.ignored_reason}")
        elif collected_metrics["error_count"]:
            error_message = (
                f"{collected_metrics['error_count']}"
                " of logs were NOT loaded into Amazon ES"
            )
            logger.error(error_message)
            logger.error(error_reason_list[:5])
            raise Exception(error_message)
        elif collected_metrics["total_log_load_count"] > 0:
            logger.info("All logs were loaded into Amazon ES")
        else:
            logger.warning("No entries were successed to load")
