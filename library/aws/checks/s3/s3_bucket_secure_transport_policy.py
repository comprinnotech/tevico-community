"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""

import boto3
import json

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class s3_bucket_secure_transport_policy(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        buckets = client.list_buckets()['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                
                policy = client.get_bucket_policy(Bucket=bucket_name)['Policy']
                policy_json = json.loads(policy)  
            except client.exceptions.ClientError:
                policy_json = None

            if not policy_json:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[bucket_name] = False
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[bucket_name] = False
               
                for statement in policy_json.get("Statement", []):
                    if (
                        statement.get("Effect") == "Deny"
                        and "Condition" in statement
                        and "Action" in statement
                        and (
                            "s3:PutObject" in statement["Action"]
                            or "*" in statement["Action"]
                            or "s3:*" in statement["Action"]
                        )
                    ):
                        if "Bool" in statement["Condition"]:
                            if "aws:SecureTransport" in statement["Condition"]["Bool"]:
                                if (
                                    statement["Condition"]["Bool"][
                                        "aws:SecureTransport"
                                    ]
                                    == "false"
                                ):
                                    report.status = ResourceStatus.PASSED
                                    report.resource_ids_status[bucket_name] = True

        return report
