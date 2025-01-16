"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_policy_allows_privilege_escalation(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            # List all IAM users to check their policies
            users = client.list_users()['Users']
            # Define a set of actions that may indicate privilege escalation
            privilege_escalation_actions = set()

            # Get all policies to check for potential privilege escalation actions
            paginator = client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    policy_version = client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    policy_document = client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_version)['PolicyVersion']['Document']
                    
                    # Collect actions from each policy document
                    for statement in policy_document.get('Statement', []):
                        actions = statement.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        
                        privilege_escalation_actions.update(actions)

            def check_policies(policies):
                """Helper function to check policy documents for escalation actions"""
                for policy in policies:
                    policy_arn = policy['PolicyArn']
                    if not self.is_custom_policy(policy_arn):  # Only check custom policies
                        continue

                    policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    policy_document = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                    
                    # Check policy statements for actions that allow privilege escalation
                    for statement in policy_document.get('Statement', []):
                        actions = statement.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        
                        for action in actions:
                            if action in privilege_escalation_actions:
                                return True  # Privilege escalation action found
                return False

            # Check users for privilege escalation policies
            for user in users:
                username = user['UserName']
                attached_policies = client.list_attached_user_policies(UserName=username)['AttachedPolicies']
                inline_policies = client.list_user_policies(UserName=username)['PolicyNames']
                
                if check_policies(attached_policies):
                    report.resource_ids_status[username] = True
                else:
                    report.resource_ids_status[username] = False

            # Set overall check status
            # report.status = not any(report.resource_ids_status.values())
            if not any(report.resource_ids_status.values()):
                report.status = ResourceStatus.FAILED
            else:
                report.status = ResourceStatus.PASSED
        
        except Exception as e:
            report.status = ResourceStatus.FAILED
        
        return report

    def is_custom_policy(self, policy_arn):
        """Check if a policy is custom by examining the ARN"""
        return not policy_arn.startswith('arn:aws:iam::aws:policy/')








































































































