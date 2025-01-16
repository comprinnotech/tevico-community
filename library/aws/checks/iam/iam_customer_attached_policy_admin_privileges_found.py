"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_customer_attached_policy_admin_privileges_found(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        # Initialize the IAM client
        iam_client = connection.client('iam')
        # print("[INFO] Initialized IAM client.")

        # Fetch all users
        users = iam_client.list_users()['Users']
        # print(f"[INFO] Retrieved {len(users)} IAM users.")

        findings = []

        for user in users:
            user_name = user['UserName']
            # print(f"[INFO] Processing IAM user: {user_name}")

            # Fetch attached policies for the user (only custom managed policies)
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            # print(f"[INFO] {user_name} has {len(attached_policies)} attached custom policies.")

            for policy in attached_policies:
                policy_arn = policy['PolicyArn']

                # Fetch policy details to check if it's a custom managed policy
                policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                if policy_details['Policy']['Arn'].startswith('arn:aws:iam::aws:policy/'):
                    # Skip AWS managed policies
                    # print(f"[INFO] Skipping AWS managed policy: {policy['PolicyName']}")
                    continue

                # print(f"[INFO] Checking details for attached custom policy: {policy['PolicyName']}")

                # Get the policy document
                policy_version = policy_details['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                # Check if the policy grants full administrative privileges
                if 'Statement' in policy_document:
                    for statement in policy_document['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            # Check if actions allow all actions and resources ('*:*' means admin privileges)
                            if actions == "*" and resources == "*":
                                # print(f"[WARNING] Custom managed policy {policy['PolicyName']} grants full administrative privileges to user {user_name}.")
                                findings.append(f"User {user_name} has custom managed policy {policy['PolicyName']} with full administrative privileges.")
                                break  # Stop after detecting full admin privileges
                            elif isinstance(actions, list) and "*" in actions and isinstance(resources, list) and "*" in resources:
                                # print(f"[WARNING] Custom managed policy {policy['PolicyName']} grants full administrative privileges to user {user_name}.")
                                findings.append(f"User {user_name} has custom managed policy {policy['PolicyName']} with full administrative privileges.")
                                break  # Stop after detecting full admin privileges
                    else:
                        # print(f"[INFO] Custom managed policy {policy['PolicyName']} does not grant full administrative privileges.")
                        pass
                else:
                    # print(f"[INFO] No statements found in policy {policy['PolicyName']}.")
                    pass

        # Determine report status based on findings
        if findings:
            report.status = ResourceStatus.FAILED  # Indicate that the check failed
            report.resource_ids_status = {user['UserName']: False for user in users}  # Mark users as having issues
            report.report_metadata = {"findings": findings}  # Store findings in report metadata
            # print(f"[FAIL] Administrative privileges found for {len(findings)} policies.")
        else:
            report.status = ResourceStatus.PASSED  # Indicate that the check passed
            report.resource_ids_status = {user['UserName']: True for user in users}  # Mark all users as having no issues
            # print("[PASS] No administrative privileges found in attached custom policies.")

        return report

    
# The check will **pass** if no attached custom managed policies grant full administrative privileges (i.e., no policies have both `"Action": "*"` and `"Resource": "*"`).
# It will **fail** if any custom managed policy grants full administrative privileges to any user.
