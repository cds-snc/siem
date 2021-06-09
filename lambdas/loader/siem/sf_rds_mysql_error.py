# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import ipaddress
import re

from siem import utils

# REGEXP
RE_AUTH_FAILED = re.compile(
    r"Access denied for user '(?P<mysql_username>[^']*)'"
    r"@'(?P<mysql_host>[^']*)'")
RE_UNKNOWN_DB = re.compile("Unknown database '(?P<mysql_database>[^']*)'")


def transform(logdata):
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']

    m_failed = RE_AUTH_FAILED.match(logdata['mysql_message'])
    if m_failed:
        logdata['event']['category'] = 'authentication'
        logdata['event']['type'] = 'start'
        logdata['event']['action'] = 'failed'
        logdata['event']['outcome'] = 'failure'

        logdata['mysql_username'] = m_failed.group('mysql_username')
        if 'user' not in logdata:
            logdata['user'] = {}
        logdata['user']['name'] = m_failed.group('mysql_username')

        host = m_failed.group('mysql_host')
        logdata['mysql_host'] = host
        if 'source' not in logdata:
            logdata['source'] = {}
        logdata['source']['address'] = host
        try:
            ipaddress.ip_address(host)
            logdata['source']['ip'] = host
        except ValueError:
            pass

    m_unknown_db = RE_UNKNOWN_DB.match(logdata['mysql_message'])
    if m_unknown_db:
        logdata['event']['category'] = 'authentication'
        logdata['event']['type'] = 'start'
        logdata['event']['action'] = 'failed'
        logdata['event']['outcome'] = 'failure'
        logdata['mysql_database'] = m_unknown_db.group('mysql_database')
        logdata['rds']['database_name'] = m_unknown_db.group('mysql_database')

    logdata = utils.convert_underscore_field_into_dot_notation(
        'mysql', logdata)
    return logdata
