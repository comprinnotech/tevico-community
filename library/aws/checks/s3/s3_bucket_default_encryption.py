"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class s3_bucket_default_encryption(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        s3_client = connection.client('s3')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Get all buckets
            paginator = s3_client.get_paginator("list_buckets")
            bucket_list = []

            for page in paginator.paginate():
                bucket_list.extend(page.get("Buckets", []))

            if not bucket_list:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No S3 buckets found."
                    )
                )
                return report

            # Check encryption for each bucket
            for bucket in bucket_list:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Check if bucket has default encryption
                    encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    encryption_rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    
                    if encryption_rules:
                        # Get encryption details for better reporting
                        encryption_type = None
                        kms_master_key_id = None
                        
                        for rule in encryption_rules:
                            if 'ApplyServerSideEncryptionByDefault' in rule:
                                default_encryption = rule['ApplyServerSideEncryptionByDefault']
                                encryption_type = default_encryption.get('SSEAlgorithm')
                                kms_master_key_id = default_encryption.get('KMSMasterKeyID')
                                break
                        
                        # Check if bucket encryption uses KMS (preferred) or AES256
                        if encryption_type == 'aws:kms':
                            key_description = f"KMS key: {kms_master_key_id}" if kms_master_key_id else "KMS key"
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=bucket_arn),
                                    status=CheckStatus.PASSED,
                                    summary=f"S3 bucket {bucket_name} has default encryption enabled using {key_description}."
                                )
                            )
                        elif encryption_type == 'AES256':
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=bucket_arn),
                                    status=CheckStatus.PASSED,
                                    summary=f"S3 bucket {bucket_name} has default encryption enabled using Amazon S3-managed keys (SSE-S3)."
                                )
                            )
                        else:
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=AwsResource(arn=bucket_arn),
                                    status=CheckStatus.PASSED,
                                    summary=f"S3 bucket {bucket_name} has default encryption enabled using {encryption_type}."
                                )
                            )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} does not have default encryption enabled."
                            )
                        )
                
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} does not have default encryption enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to retrieve encryption settings for S3 bucket {bucket_name}.",
                                exception=str(e)
                            )
                        )
                except (BotoCoreError, Exception) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=bucket_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Failed to retrieve encryption settings for S3 bucket {bucket_name}.",
                            exception=str(e)
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Encountered an error while retrieving S3 buckets.",
                    exception=str(e)
                )
            )

        return report
