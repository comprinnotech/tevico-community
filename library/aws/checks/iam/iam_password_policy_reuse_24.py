"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_reuse_24(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        
        # Initialize the report
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True if not explicitly set to False

        try:
            # Create the IAM client
            client = connection.client('iam')
            
            # Retrieve the account password policy
            account_password_policy = client.get_account_password_policy()
            password_policy = account_password_policy['PasswordPolicy']
            
            # Check the password reuse prevention value
            reuse_prevention = password_policy.get('ReusePrevention', 0)
            
            # Update the report status based on the reuse prevention policy
            if reuse_prevention < 24:
                report.passed = False
            report.resource_ids_status['password_policy'] = reuse_prevention >= 24

        except (ClientError, BotoCoreError):
            # Handle AWS API errors
            report.passed = False
            report.resource_ids_status['password_policy'] = False

        except Exception:
            # Handle unexpected exceptions
            report.passed = False

        # Return the final report
        return report
