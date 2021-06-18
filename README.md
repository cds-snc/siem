# Security Information and Event Management

This repository contains the code required to deploy a Security Information and Event Management (SIEM) system for the [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/). It automatically draws data from the `security` and `logging` accounts set up as part of the Landing Zone products and exposes threat events through ElasticSearch and Kibana.

This repository is largely a replicant of the work available in [this respositoy](https://github.com/aws-samples/siem-on-amazon-elasticsearch-service). The major differences are:

- Using Terraform instead of CloudFormation / CDK
- Deploying ElasticSearch using Terraform instead of a Lambda
- Rewrite of the `ip-geolocation` lambda to include integration tests
- Added integration tests for the `loader` lambda

These changes bring the code more inline with CDS development practices and allow us to support the product in the long term, as well as making the code re-usable across other organisations.

### Open source considerations

By open sourcing this product, we are revealing information to potential adversaries about what threat indicators we are paying attention to and where potential blind spots might be. As a result we are not including our configurations on what data we are monitoring and alerting on. However, CDS practices defence in depth and this is not the only threat analysis tool available to us, nor is it comprehensive. We also believe working in the open is the way forward on ensuring we catch issues we may not otherwise in addition to all the goodness reusability of code brings.

We recommend that you use this tool as part of a larger suite of security tools rather than relying on this as your only tool. A good place to start with AWS is this [blog post](https://aws.amazon.com/blogs/security/top-10-security-items-to-improve-in-your-aws-account/).

### Configuration

You will need the following environment variables:

| Name                  | Purpose                                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| AWS_ACCESS_KEY_ID     | Access key ID to deploy resources to AWS.                                                                                                           |
| AWS_SECRET_ACCESS_KEY | Access key secret to deploy resources to AWS.                                                                                                       |
| KIBANA_ADMIN_ROLE     | Username for Kibana admin.                                                                                                                          |
| LANDING_ZONE_PREFIX   | The prefix in the `logging` account S3 bucket set up by the [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/). |
| LOGGING_ACCOUNT       | The account ID for the `logging` account set up by the [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/).      |
| MAXMIND_KEY           | The API key for the [MaxMind](https://www.maxmind.com/en/home) IP database.                                                                         |
| SECURITY_ACCOUNT      | The account ID for the `security` account set up by the [AWS Landing Zone](https://aws.amazon.com/solutions/implementations/aws-landing-zone/).     |
| SIEM_ACCOUNT          | The account ID for the account you want to set up the SIEM in.                                                                                      |

### Requires
- Terraform (https://www.terraform.io/)
- Terragrunt (https://terragrunt.gruntwork.io/)

### Why are we using Terragrunt?
The promise of Terragrunt is to make it easier to maintain Terraform code by providing a wrapper around modules, adhering to "Don't repeat yourself" (DRY) configuration as well as better remote state management. For a complete explanation of features, take a look at the [excellent documentation](https://terragrunt.gruntwork.io/docs/#features).

### How is this repository structured?
The Terraform code contained in `aws` is split into several independent modules that all use their own remote Terraform state file. These modules know nothing about Terragrunt and are used by Terragrunt as simple infrastructure definitions.

### What is each Terraform module

#### `aws/cloud-trail`
This module sets up the replication role for copy data from the centralized log S3 bucket in the `logging` account. As the bucket is managed by the landing zone CloudFormation, the replication rule needs to be manually added to the bucket.

#### `aws/guard-duty`
This module creates a new bucket in the SIEM account and attaches it to the `loader` lambda. Additionally it configures GuardDuty to egress information from the `security` account into bucket so that it can be loaded in to the SIEM.

#### `aws/security-hub`
This module creates a S3 bucket, a kinesis stream and an event bridge resource to egress SecurityHub information from the `security` account. The S3 bucket then replicates its logs into the primary SIEM loading account.

#### `aws/siem/elasticsearch`
This module sets up the base ElasticSearch instance inside the SIEM account without any specific configuration.

#### `aws/siem/elasticsearch_loader`
This module sets up the `loader` lambda inside the SIEM account and configures the ElasticSearch instance to handle the logs egressed from that lambda. It sets up all the indexes as well as creates the backend roles to allow for backups.

#### `aws/siem/ip-geolocation`
This module sets up the `ip-geolocation` lambda inside the SIEM account and adds an S3 bucket to download the latest MaxMind IP database on a daily basis.

#### `aws/siem/s3-replication`
This module configures the primary S3 bucket that handles the log ingress to accept replication data from the `security-hub` and `cloud-trail`. Because there is a dependency chain between a lot of the modules this one affects resources created in the `aws/siem/elasticsearch_loader` module with data from the above mentioned modules.

### Security
See SECURITY.md for more information.

### License
This library is licensed under the MIT-0 License. See the LICENSE file.

This product uses GeoLite2 data created by MaxMind and licensed under CC BY-SA 4.0, available from https://www.maxmind.com.