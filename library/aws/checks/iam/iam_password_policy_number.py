"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-10-10
"""

import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check

class iam_password_policy_number(Check):

   def execute(self, connection: boto3.Session) -> CheckReport:
    report = CheckReport(name=__name__)
    try:
        client = connection.client('iam')
        account_password_policy = client.get_account_password_policy()

        password_policy = account_password_policy['PasswordPolicy']
        requires_number = password_policy.get('RequireNumbers', False)

        if requires_number:
            report.passed = True
        else:
            report.passed = False

    except client.exceptions.NoSuchEntityException:
        # No password policy exists
        report.passed = False
    except Exception as e:
        # Handle any other unexpected errors
        report.passed = False

    return report

