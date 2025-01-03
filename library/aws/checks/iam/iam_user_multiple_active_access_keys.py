"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_user_multiple_active_access_keys(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Start with passed = True
        
        try:
            client = connection.client('iam')
            # List all IAM users
            users = client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                # List access keys for each user
                access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
                active_keys_count = sum(1 for key in access_keys if key['Status'] == 'Active')
                
                if active_keys_count > 1:
                    # User has multiple active access keys - this is a violation
                    report.resource_ids_status[username] = False  # Mark as non-compliant
                    report.passed = False  # Overall check fails
                else:
                    # User has 0 or 1 active access key - this is compliant
                    report.resource_ids_status[username] = True  # Mark as compliant
            
        except (ClientError, BotoCoreError):
            report.passed = False
            report.resource_ids_status['Error checking access keys'] = False
            
        return report
