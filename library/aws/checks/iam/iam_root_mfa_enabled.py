"""
AUTHOR: Supriyo Bhakat 
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-10-10
"""

import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check

class iam_root_mfa_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        client = connection.client('iam')

        try:
            # Get account summary to check MFA status for the root account
            account_summary = client.get_account_summary()
            
            # Extract the value indicating if root MFA is enabled
            root_mfa_enabled = account_summary['SummaryMap']['AccountMFAEnabled']

            # Check if MFA is enabled for the root user
            if root_mfa_enabled == 1:
                report.passed = True
            else:
                report.passed = False

        except Exception as e:
            report.passed = False

        return report
