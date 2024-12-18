"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""
import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_no_root_access_keys(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
           
            response = client.list_access_keys()

           
            has_active_root_keys = any(
                access_key['Status'] == 'Active' for access_key in response['AccessKeyMetadata']
            )

            if has_active_root_keys:
                report.passed = False
                report.resource_ids_status['root_account'] = False
            else:
                report.passed = True
                report.resource_ids_status['root_account'] = True

            if not any(status for status in report.resource_ids_status.values()):
                report.passed = False

        except Exception:
            report.passed = False
            report.resource_ids_status['root_account'] = False

        return report
