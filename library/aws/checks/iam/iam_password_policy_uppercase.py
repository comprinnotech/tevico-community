"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.check.check import Check


class iam_password_policy_uppercase(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        
       
        try:
            password_policy = client.get_account_password_policy()
        except client.exceptions.NoSuchEntityException:
            return report

        uppercase_required = password_policy.get('RequireUppercaseCharacters', False)
        
        
        if uppercase_required:
            report.status = CheckStatus.PASSED
        else:
            report.status = CheckStatus.FAILED

        return report
