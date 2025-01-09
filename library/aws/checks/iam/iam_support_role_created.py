"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""


import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_support_role_created(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')
        try:
            # List all IAM roles
            roles = client.list_roles()['Roles']
            support_role_found = False
            
            for role in roles:
                role_name = role['RoleName']
                # Check if the role name indicates it is related to support
                if "support" in role_name.lower():

                    support_role_found = True
                    report.resource_ids_status[role_name] = True
            
            if not support_role_found:

                report.passed = False
            else:
                report.passed = True
            
        except Exception as e:

            report.passed = False
        
        return report
