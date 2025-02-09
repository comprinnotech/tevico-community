"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_password_policy_number(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        try:
            client = connection.client('iam')
            account_password_policy = client.get_account_password_policy()
            password_policy = account_password_policy['PasswordPolicy']
            requires_number = password_policy.get('RequireNumbers', False)

            report.passed = requires_number
            report.resource_ids_status['password_policy'] = requires_number

        except client.exceptions.NoSuchEntityException:
            report.passed = False
            report.resource_ids_status['password_policy'] = False
        except Exception:
            report.passed = False

        return report
