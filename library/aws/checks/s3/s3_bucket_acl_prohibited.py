"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class s3_bucket_acl_prohibited(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        buckets = client.list_buckets()['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            acl = client.get_bucket_acl(Bucket=bucket_name)
            owner_enforced = False

            if 'BucketOwnerEnforced' in acl.get('Owner', {}):
                owner_enforced = True

            if owner_enforced:
                report.status = CheckStatus.PASSED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=bucket_name),
                        status=CheckStatus.PASSED,
                        summary=''
                    )
                )
            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=bucket_name),
                        status=CheckStatus.FAILED,
                        summary=''
                    )
                )

        return report
