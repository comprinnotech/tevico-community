"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_lowercase(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        
        # Retrieve the password policy
        try:
            password_policy = client.get_account_password_policy()
        except client.exceptions.NoSuchEntityException:
            return report

        lowercase_required = password_policy.get('RequireLowercaseCharacters', False)
        
        # Check if the lowercase flag is set
        if lowercase_required:
            report.passed = True
        else:
            report.passed = False

        return report
