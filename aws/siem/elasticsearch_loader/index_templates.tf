resource "elasticsearch_index_template" "log_aws" {
  name = "log_aws"
  body = <<EOF
{
  "index_patterns": ["log-*"],
  "order": 1,
  "settings": {
    "index.mapping.ignore_malformed": true,
    "number_of_shards": "3"
  },
  "mappings" : {
    "dynamic_templates": [{
      "strings": {
        "match_mapping_type": "string",
        "mapping": {"type": "keyword"}
      }
    }],
    "properties": {
      "@timestamp": { "type": "date" },
      "@message": { "type": "text" },
      "destination.ip": { "type": "ip" },
      "destination.packets": { "type": "long" },
      "destination.bytes": { "type": "long" },
      "destination.port": { "type": "integer" },
      "destination.geo.location": {  "type": "geo_point" },
      "destination.as.number": {  "type": "integer" },
      "error.message": { "type": "text" },
      "event.ingested": { "type": "date" },
      "event.severity": { "type": "long" },
      "http.request.bytes": { "type": "long" },
      "http.response.bytes": { "type": "long" },
      "http.response.status_code": { "type": "short" },
      "http.version": { "type": "keyword" },
      "host.hostname": { "type": "keyword" },
      "log.level": { "type": "keyword" },
      "network.bytes": { "type": "integer" },
      "network.iana_number":  { "type": "short" },
      "network.packets":  { "type": "integer" },
      "process.pid": { "type": "integer" },
      "rule.id": { "type": "keyword" },
      "rule.version": { "type": "keyword" },
      "source.ip": { "type": "ip" },
      "source.packets": { "type": "long" },
      "source.bytes": { "type": "long" },
      "source.port": { "type": "integer" },
      "source.geo.location": {  "type": "geo_point" },
      "source.as.number": {  "type": "integer" },
      "url.full": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "url.original": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "user.name": { "type": "keyword" },
      "user_agent.original": {"type": "keyword","fields": {"text" : {"type" : "text"} }}
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws_aws" {
  name = "log-aws_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-*"],
  "order": 2,
  "mappings" : {
    "properties": {
      "apiVersion": { "type": "keyword" },
      "SchemaVersion": { "type": "keyword" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-cloudtrail_aws" {
  name = "log-aws-cloudtrail_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-cloudtrail-*"],
  "order": 3,
  "settings": {
    "index.mapping.total_fields.limit": 5000,
    "index.mapping.ignore_malformed": true
  },
  "mappings" : {
    "properties": {
      "awsRegion": { "type": "keyword" },
      "errorCode": { "type": "keyword" },
      "eventID": { "type": "keyword" },
      "additionalEventData.bytesTransferredIn": {"type": "float"},
      "additionalEventData.bytesTransferredOut": {"type": "float"},
      "additionalEventData.vpcEndpointId": { "type": "keyword" },
      "requestParameters.authParameters": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.endTime": {"type": "date", "format": "MMM d, yyyy h:mm:ss a||epoch_millis"},
      "requestParameters.MaxResults": {"type": "integer"},
      "requestParameters.instanceType": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.maxItems": {"type": "integer"},
      "requestParameters.maxResults": {"type": "integer"},
      "requestParameters.NotificationConfiguration.QueueConfiguration.Id": {"type": "keyword"},
      "requestParameters.attribute": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.bucketPolicy.Statement": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.CreateFleetRequest.TagSpecification.Tag.Value": {"type": "keyword"},
      "requestParameters.CreateLaunchTemplateVersionRequest.LaunchTemplateData.TagSpecification.Tag.Value": {"type": "keyword"},
      "requestParameters.CreateSnapshotsRequest.TagSpecification.Tag.Value": {"type": "keyword"},
      "requestParameters.DescribeFlowLogsRequest": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateVersion.content": {"type": "keyword"},
      "requestParameters.Tagging.TagSet.Tag.Value": {"type": "keyword"},
      "requestParameters.containerOverrides.environment.value": {"type": "keyword"},
      "requestParameters.content": {"type": "keyword", "fields": {"text": {"type": "text"}}},
      "requestParameters.ebsOptimized": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.filter": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.groupDescription": {"type": "keyword"},
      "requestParameters.iamInstanceProfile": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.logStreamNamePrefix": {"type": "keyword"},
      "requestParameters.overrides.containerOverrides.environment.value": {"type": "keyword"},
      "requestParameters.partitionInputList": {"type": "text"},
      "requestParameters.principal": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.result": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.searchExpression.subExpressions.subExpressions.filters.value": {"type": "keyword"},
      "requestParameters.size": {"type": "integer"},
      "requestParameters.source": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.sort": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.sortBy": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.startTime":  {"type": "date", "format": "MMM d, yyyy h:mm:ss a||epoch_millis"},
      "requestParameters.status": {"type": "keyword", "fields": {"text": {"type": "text"}}},
      "requestParameters.tags.value": {"type": "keyword"},
      "requestParameters.target": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.subnets": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "requestParameters.value": {"type": "keyword"},
      "requestParameters.vpc": {"type": "keyword"},
      "responseElements.CreateLaunchTemplateVersionResponse.launchTemplateVersion.launchTemplateData.tagSpecificationSet.item.tagSet.item.value": {"type": "keyword"},
      "responseElements.CreateSnapshotsResponse.snapshotSet.item.tagSet.item.value": {"type": "keyword"},
      "responseElements.availabilityZones": {"type": "keyword"},
      "responseElements.dBSubnetGroup": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "responseElements.description": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "responseElements.endpoint": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "responseElements.errors.partitionValues": {"type": "keyword"},
      "responseElements.multiAZ": {"type": "keyword"},
      "responseElements.policy.value": {"type": "keyword","fields": {"text": {"type" : "text"}}},
      "responseElements.role": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "responseElements.subnets": {"type": "keyword","fields": {"text" : {"type" : "text"} }},
      "responseElements.tasks.overrides.containerOverrides.environment.value": {"type": "keyword"},
      "responseElements.version": {"type": "keyword"},
      "responseElements.createTime": {"type": "date", "format": "epoch_millis||MMM d, yyyy h:mm:ss a"},
      "responseElements.createdDate": {"type": "date", "format": "strict_date_optional_time||MMM d, yyyy h:mm:ss a"},
      "responseElements.lastModified": {"type": "date", "format": "strict_date_optional_time||MMM d, yyyy h:mm:ss a"},
      "responseElements.lastUpdatedDate": {"type": "date", "format": "strict_date_optional_time||MMM d, yyyy h:mm:ss a"},
      "serviceEventDetails.eventRequestDetails": {"type": "keyword","fields": {"text" : {"type" : "text"} }}
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-vpcflowlogs_aws" {
  name = "log-aws-vpcflowlogs_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-vpcflowlogs-*"],
  "order": 4,
  "mappings" : {
    "properties": {
      "version": { "type": "keyword" },
      "account_id": { "type": "keyword" },
      "interface_id": { "type": "keyword" },
      "srcaddr": { "type": "ip" },
      "dstaddr": { "type": "ip" },
      "srcport": { "type": "integer" },
      "dstport": { "type": "integer" },
      "protocol": { "type": "short" },
      "packets": { "type": "integer" },
      "bytes": { "type": "integer" },
      "start": { "type": "date" , "format":  "epoch_second"},
      "end": { "type": "date",  "format":  "epoch_second"},
      "action": { "type": "keyword" },
      "log_status": { "type": "keyword" },
      "vpc_id": { "type": "keyword" },
      "subnet_id": { "type": "keyword" },
      "instance_id": { "type": "keyword" },
      "tcp_flags": { "type": "byte" }
      }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-networkfirewall_aws" {
  name = "log-aws-networkfirewall_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-networkfirewall-*"],
  "order": 5,
  "mappings" : {
    "properties": {
      "event.alert.severity": { "type": "long" },
      "event.alert.signature_id": { "type": "keyword" },
      "event.alert.rev": { "type": "keyword" },
      "event.dest_ip": { "type": "ip" },
      "event.dest_port": { "type": "long" },
      "event.http.length": { "type": "long" },
      "event.netflow.bytes": { "type": "long" },
      "event.netflow.max_ttl": { "type": "long" },
      "event.netflow.min_ttl": { "type": "long" },
      "event.netflow.pkts": { "type": "long" },
      "event.src_ip": { "type": "ip" },
      "event.src_port": { "type": "long" },
      "event.tcp.tcp_flag": { "type": "keyword" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-securityhub_aws" {
  name = "log-aws-securityhub_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-securityhub-*"],
  "order": 6,
  "mappings" : {
    "properties": {}
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-guardduty_aws" {
  name = "log-aws-guardduty_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-guardduty-*"],
  "order": 7,
  "settings": {
    "number_of_shards": "1"
  },
  "mappings": {
    "properties": {
      "description": {  "type": "text" },
      "resource.instanceDetails.launchTime": {  "type": "date" },
      "resource.instanceDetails.networkInterfaces.privateIpAddress": {  "type": "ip" },
      "resource.instanceDetails.networkInterfaces.privateIpAddresses.privateIpAddress": {  "type": "ip" },
      "resource.instanceDetails.networkInterfaces.publicIp": {  "type": "ip" },
      "service.action.awsApiCallAction.remoteIpDetails.geoLocation": {  "type": "geo_point" },
      "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4": {  "type": "ip" },
      "service.action.awsApiCallAction.remoteIpDetails.ipAddressV6": {  "type": "ip" },
      "service.action.awsApiCallAction.remoteIpDetails.organization.asn": {  "type": "integer" },
      "service.action.networkConnectionAction.localIpDetails.ipAddressV4": {  "type": "ip" },
      "service.action.networkConnectionAction.localPortDetails.port": {  "type": "integer" },
      "service.action.networkConnectionAction.remoteIpDetails.geoLocation": { "type": "geo_point" },
      "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {  "type": "ip" },
      "service.action.networkConnectionAction.remoteIpDetails.organization.asn": {  "type": "integer" },
      "service.action.portProbeAction.portProbeDetails.localIpDetails.ipAddressV4": {  "type": "ip" },
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.geoLocation": {  "type": "geo_point" },
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4": {  "type": "ip" },
      "service.additionalInfo.inBytes": {"type": "long"},
      "service.additionalInfo.apiCalls.firstSeen": {"type": "date"},
      "service.additionalInfo.apiCalls.lastSeen": {"type": "date"},
      "service.additionalInfo.localPort": {"type": "integer"},
      "service.additionalInfo.newPolicy.maxPasswordAge": {"type": "short"},
      "service.additionalInfo.newPolicy.minimumPasswordLength": {"type": "short"},
      "service.additionalInfo.newPolicy.passwordReusePrevention": {"type": "short"},
      "service.additionalInfo.oldPolicy.maxPasswordAge": {"type": "short"},
      "service.additionalInfo.oldPolicy.minimumPasswordLength": {"type": "short"},
      "service.additionalInfo.oldPolicy.passwordReusePrevention": {"type": "short"},
      "service.additionalInfo.outBytes": {"type": "long"},
      "service.additionalInfo.recentCredentials.ipAddressV4": {"type": "ip"},
      "service.additionalInfo.unusual": {  "type": "text" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-elb_aws" {
  name = "log-aws-elb_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-elb-*"],
  "order": 8,
  "mappings" : {
    "properties": {
      "timestamp": { "type": "date" },
      "backend_ip": { "type": "ip" },
      "backend_port": { "type": "integer" },
      "backend_processing_time": { "type": "half_float" },
      "backend_status_code": { "type": "short" },
      "client_ip": { "type": "ip" },
      "client_port": { "type": "integer" },
      "connection_time": { "type": "integer" },
      "destination_ip": { "type": "ip" },
      "destination_port": { "type": "integer" },
      "elb_status_code": { "type": "short" },
      "http_port": { "type": "integer" },
      "http_version": { "type": "keyword" },
      "matched_rule_priority": { "type": "integer" },
      "received_bytes": { "type": "integer" },
      "request_processing_time": { "type": "half_float" },
      "response_processing_time": { "type": "half_float" },
      "request_creation_time": { "type": "date" },
      "sent_bytes": { "type": "integer" },
      "target_ip": { "type": "ip" },
      "target_port": { "type": "integer" },
      "target_status_code": { "type": "short" },
      "target_processing_time": { "type": "half_float" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-s3accesslog_aws" {
  name = "log-aws-s3accesslog_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-s3accesslog-*"],
  "order": 9,
  "mappings" : {
    "properties": {
      "BytesSent": { "type": "integer" },
      "HTTPstatus": { "type": "short" },
      "ObjectSize": { "type": "integer" },
      "RemoteIP": { "type": "ip" },
      "RequestDateTime": {"type": "date", "format": "dd/MMM/yyyy:hh:mm:ss a"},
      "TotalTime": { "type": "integer" },
      "TurnAroundTime": { "type": "integer" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-waf_aws" {
  name = "log-aws-waf_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-waf-*"],
  "order": 10,
  "mappings" : {
    "properties": {
      "formatVersion": { "type": "keyword" },
      "httpRequest.clientIp": { "type": "ip" },
      "timestamp": { "type": "date", "format": "epoch_millis"}
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-cloudfront_aws" {
  name = "log-aws-cloudfront_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-cloudfront-*"],
  "order": 11,
  "mappings" : {
    "properties": {
      "c_ip": { "type": "ip" },
      "c_port": { "type": "integer" },
      "cs_bytes": { "type": "long" },
      "cs_headers_count": { "type": "short" },
      "date_time": { "type": "date" },
      "sc_bytes": { "type": "long" },
      "sc_content_len": { "type": "long" },
      "sc-range-start": { "type": "long" },
      "sc-range-end": { "type": "long" },
      "sc_status": { "type": "keyword" },
      "time_taken": { "type": "half_float" },
      "time_to_first_byte": { "type": "half_float" },
      "timestamp": { "type": "date", "format": "epoch_second"}
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-r53resolver_aws" {
  name = "log-aws-r53resolver_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-r53resolver-*"],
  "order": 12,
  "mappings" : {
    "properties": {
      "answers": { "type": "object" },
      "query_timestamp": { "type": "date" },
      "srcaddr": { "type": "ip" },
      "srcport": { "type": "integer"},
      "version": {"type": "keyword"}
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-linux_aws" {
  name = "log-linux_aws"
  body = <<EOF
{
  "index_patterns": ["log-linux-*"],
  "order": 13,
  "mappings" : {
    "properties": {
      "syslog_timestamp": { "type": "keyword" },
      "syslog_message": { "type": "text" },
      "pid": { "type": "integer" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-rds_aws" {
  name = "log-aws-rds_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-rds-*"],
  "order": 14,
  "mappings" : {
    "properties": {
      "rds.cluster_identifier": { "type": "keyword" },
      "rds.instance_identifier": { "type": "keyword" },
      "rds.database_name": { "type": "keyword" },
      "rds.message": { "type": "text" },
      "rds.query": { "type": "text" },
      "rds.query_time": { "type": "float" },
      "mysql.lock_time": { "type": "float" },
      "mysql.message": { "type": "text" },
      "mysql.object": { "type": "keyword" },
      "mysql.query": { "type": "text" },
      "mysql.query_id": { "type": "long" },
      "mysql.query_time": { "type": "float" },
      "mysql.retcode": { "type": "keyword" },
      "mysql.source_ip": { "type": "ip" },
      "mysql.thread_id": { "type": "long" },
      "mysql.timestamp": { "type": "date", "format": "date_optional_time||yyyyMMdd HH:mm:ss"},
      "postgresql.duration_ms": { "type": "float" },
      "postgresql.message": { "type": "text" },
      "postgresql.query": { "type": "text" },
      "postgresql.session_time_seconds": { "type": "float" },
      "postgresql.source_port": { "type": "integer" },
      "postgresql.pid": { "type": "integer" },
      "postgresql.thread_id": { "type": "integer" },
      "postgresql.timestamp": { "type": "date" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "log-aws-msk_aws" {
  name = "log-aws-msk_aws"
  body = <<EOF
{
  "index_patterns": ["log-aws-msk-*"],
  "order": 15,
  "mappings" : {
    "properties": {
      "msk.broker_id": { "type": "keyword" },
      "msk.max_lag": { "type": "long" },
      "msk.message": {"type": "text" },
      "msk.sum_lag": { "type": "long" },
      "msk.time_lag": { "type": "long" }
    }
  }
}
EOF
}

resource "elasticsearch_index_template" "ism-history-indices_aws" {
  name = "ism-history-indices_aws"
  body = <<EOF
{
  "index_patterns": [
    ".opendistro-ism-managed-index-history-*"
  ],
  "order": 16,
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  }
}
EOF
}

resource "elasticsearch_index_template" "alert-history-indices_aws" {
  name = "alert-history-indices_aws"
  body = <<EOF
{
  "index_patterns": [
    ".opendistro-alerting-alert-history-*"
  ],
  "order": 17,
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 1
  }
}
EOF
}