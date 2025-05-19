"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-03-28
"""

import boto3
import json
from botocore.exceptions import BotoCoreError, ClientError

from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class s3_bucket_secure_transport_policy(Check):
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

            # Check secure transport policy for each bucket
            for bucket in bucket_list:
                bucket_name = bucket["Name"]
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                
                try:
                    # Get bucket policy
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_str = policy_response.get('Policy', '{}')
                    policy_json = json.loads(policy_str)
                    
                    # Check if policy enforces secure transport
                    has_secure_transport = False
                    
                    for statement in policy_json.get("Statement", []):
                        # Check for deny statements that enforce HTTPS
                        if (statement.get("Effect") == "Deny" and 
                            "Condition" in statement and 
                            "Action" in statement):
                            
                            # Check if the statement applies to relevant actions
                            actions = statement.get("Action", [])
                            if not isinstance(actions, list):
                                actions = [actions]
                                
                            relevant_action = False
                            for action in actions:
                                if (action == "s3:*" or 
                                    action == "*" or 
                                    action.startswith("s3:") and "Object" in action):
                                    relevant_action = True
                                    break
                            
                            if not relevant_action:
                                continue
                                
                            # Check for secure transport condition
                            if "Bool" in statement.get("Condition", {}):
                                bool_conditions = statement["Condition"]["Bool"]
                                if "aws:SecureTransport" in bool_conditions:
                                    if bool_conditions["aws:SecureTransport"] == "false":
                                        has_secure_transport = True
                                        break
                    
                    if has_secure_transport:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.PASSED,
                                summary=f"S3 bucket {bucket_name} enforces secure transport (HTTPS) through bucket policy."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} does not enforce secure transport (HTTPS) through bucket policy."
                            )
                        )
                
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.FAILED,
                                summary=f"S3 bucket {bucket_name} does not have a bucket policy to enforce secure transport."
                            )
                        )
                    else:
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=bucket_arn),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Failed to retrieve policy for S3 bucket {bucket_name}.",
                                exception=str(e)
                            )
                        )
                except (BotoCoreError, Exception) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=bucket_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Failed to evaluate secure transport policy for S3 bucket {bucket_name}.",
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