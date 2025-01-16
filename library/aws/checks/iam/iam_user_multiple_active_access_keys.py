"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_user_multiple_active_access_keys(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        try:
            # List all IAM users
            users = client.list_users()['Users']
            for user in users:
                username = user['UserName']
                # List access keys for each user
                access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
                active_keys_count = sum(1 for key in access_keys if key['Status'] == 'Active')
                
                if active_keys_count > 1:

                    report.resource_ids_status[username] = True
                else:

                    report.resource_ids_status[username] = False
            
            report.status = not any(report.resource_ids_status.values())
        except Exception as e:

            report.status = ResourceStatus.FAILED
        return report
