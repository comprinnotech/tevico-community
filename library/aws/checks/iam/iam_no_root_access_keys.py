"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""


import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
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
                report.status = ResourceStatus.FAILED
                report.resource_ids_status['root_account'] = False
            else:
                report.resource_ids_status['root_account'] = True

            iam_users = client.list_users()['Users']

            for user in iam_users:
                user_name = user['UserName']
                response = client.list_access_keys(UserName=user_name)

                has_active_iam_keys = any(
                    access_key['Status'] == 'Active' for access_key in response['AccessKeyMetadata']
                )

                if has_active_iam_keys:
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[user_name] = False
                else:
                    report.resource_ids_status[user_name] = True

        except Exception:
            report.status = ResourceStatus.FAILED

        return report
