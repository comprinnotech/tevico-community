"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_password_policy_uppercase(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        
        # Retrieve the password policy
        try:
            password_policy = client.get_account_password_policy()
        except client.exceptions.NoSuchEntityException:
            return report

        uppercase_required = password_policy.get('RequireUppercaseCharacters', False)
        
        # Check if the uppercase flag is set
        if uppercase_required:
            report.passed = True
        else:
            report.passed = False

        return report
