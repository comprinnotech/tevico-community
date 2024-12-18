"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""


import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_policy_attached_to_only_group_or_roles(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            
            users = client.list_users()['Users']

            
            for user in users:
                username = user['UserName']
              
                attached_policies = client.list_attached_user_policies(UserName=username)['AttachedPolicies']

                if attached_policies:

                    report.resource_ids_status[username] = False  
                else:

                    report.resource_ids_status[username] = True 


            report.passed = not any(report.resource_ids_status.values())

        except Exception as e:

            report.passed = False

        return report



