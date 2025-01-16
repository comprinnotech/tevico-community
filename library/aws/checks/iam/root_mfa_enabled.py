"""
AUTHOR: Supriyo Bhakat <supriyo.bhakat@comprinno.net>
DATE: 2024-10-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class root_mfa_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        client = connection.client('iam')

        try:
            
            account_summary = client.get_account_summary()
            
           
            root_mfa_enabled = account_summary['SummaryMap']['AccountMFAEnabled']

            
            if root_mfa_enabled == 1:
                print("pass")
                report.status = ResourceStatus.PASSED
                report.resource_ids_status['root_account'] = True
                
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status['root_account'] = False
                print("MFA Is Disabled")
        except Exception as e:
            print("MFA Is Disabled")
            print(str(e))  

        return report
