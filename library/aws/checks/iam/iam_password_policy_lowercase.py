"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_lowercase(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        
        # Initialize the report
        report = CheckReport(name=__name__)
        report.passed = False
        client = connection.client('iam')

        try:
            # Retrieve the account password policy
            password_policy = client.get_account_password_policy()
            
            # Check if lowercase characters are required in the password policy
            lowercase_required = password_policy['PasswordPolicy'].get('RequireLowercaseCharacters', False)
            
            # Set report status based on the policy check
            report.passed = lowercase_required
            report.resource_ids_status['password_policy'] = lowercase_required

        except ClientError as e:
            # Handle the case where no password policy exists
            if e.response['Error']['Code'] == 'NoSuchEntity':
                report.resource_ids_status['No password policy exists'] = False
            else:
                # Handle other ClientError exceptions
                report.resource_ids_status['Failed to retrieve password policy'] = False

        except (BotoCoreError, Exception):
            # Handle BotoCoreError or unexpected exceptions
            report.resource_ids_status['Failed to check password policy'] = False

        # Return the final report
        return report
