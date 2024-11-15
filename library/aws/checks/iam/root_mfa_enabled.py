"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class root_mfa_enabled(Check):

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
                print("pass")
                report.passed = True
                report.resource_ids_status['root_account'] = True
                
            else:
                report.passed = False
                report.resource_ids_status['root_account'] = False
                print("MFA Is Disabled")
        except Exception as e:
            print("MFA Is Disabled")
            print(str(e))  # Log the error in the resource status

        return report
