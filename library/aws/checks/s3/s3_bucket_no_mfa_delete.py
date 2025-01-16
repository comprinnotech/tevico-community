"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class s3_bucket_no_mfa_delete(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('s3')
        buckets = client.list_buckets()['Buckets']

        for bucket in buckets:
            bucket_name = bucket['Name']
           
            versioning = client.get_bucket_versioning(Bucket=bucket_name)
            mfa_delete = versioning.get('MFADelete', 'Disabled')

            if mfa_delete == 'Enabled':
                report.status = ResourceStatus.PASSED
                report.resource_ids_status[bucket_name] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[bucket_name] = False

        return report
