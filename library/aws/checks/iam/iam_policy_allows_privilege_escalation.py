"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_policy_allows_privilege_escalation(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless a privilege escalation is found
        report.passed = True
        report.resource_ids_status = {}

        # Privilege escalation patterns to check in policies
        privilege_escalation_actions = [
            "iam:CreatePolicy",
            "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy",
            "iam:AttachRolePolicy",
            "iam:UpdateAssumeRolePolicy",
            "iam:PassRole",
            "sts:AssumeRole",
            "iam:PutRolePolicy",
            "iam:PutUserPolicy",
            "iam:CreateAccessKey",
            "iam:UpdateLoginProfile",
            "iam:DeleteLoginProfile",
        ]

        try:
            # List all managed and inline policies
            policies = client.list_policies(Scope='Local', OnlyAttached=False)['Policies']

            for policy in policies:
                
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']

                # Get the policy document
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                # Check statements in the policy
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]  # Ensure it's a list for single statements

                for statement in statements:
                    # Get the actions and resources
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', '*')
                    if isinstance(actions, str):
                        actions = [actions]  # Convert single action to a list

                    # Track potential privilege escalation actions
                    matched_actions = []

                    for action in actions:
                        if action in privilege_escalation_actions or action == "*":
                            matched_actions.append(action)

                    if matched_actions:
                        # If the policy allows privilege escalation, capture all matched actions
                        report.passed = False
                        report.resource_ids_status[f"Policy {policy_name} allows privilege escalation with actions {matched_actions}"] = False
                    else:
                        # If no privilege escalation actions are found
                        report.resource_ids_status[f"Policy {policy_name} does not allow privilege escalation"] = True

        except Exception as e:
            # Handle errors such as network issues or IAM permission issues
            logging.error(f"Error while checking privilege escalation in policies: {e}")
            report.passed = False
            report.resource_ids_status["Error occurred while checking privilege escalation"] = False

        return report
