"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11
"""

import boto3
from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check

class iam_inline_policy_admin_privileges_found(Check):
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

            # Check inline policies for the user
            inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
            # print(f"[INFO] {user_name} has {len(inline_policies)} inline policies.")

            for policy_name in inline_policies:
                # print(f"[INFO] Fetching details for inline policy: {policy_name}")

                # Get the inline policy document
                policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']

                # Check if the inline policy grants full administrative privileges
                if 'Statement' in policy_document:
                    for statement in policy_document['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            # Check if actions allow all actions and resources
                            if actions == "*" and resources == "*":
                                # print(f"[WARNING] Inline policy {policy_name} grants full administrative privileges to user {user_name}.")
                                findings.append(f"User {user_name} has inline policy {policy_name} with full administrative privileges.")
                                break  # Stop after detecting full admin privileges
                            elif isinstance(actions, list) and "*" in actions and isinstance(resources, list) and "*" in resources:
                                # print(f"[WARNING] Inline policy {policy_name} grants full administrative privileges to user {user_name}.")
                                findings.append(f"User {user_name} has inline policy {policy_name} with full administrative privileges.")
                                break  # Stop after detecting full admin privileges
                    else:
                        # print(f"[INFO] Inline policy {policy_name} does not grant full administrative privileges.")
                        pass
                else:
                    # print(f"[INFO] No statements found in policy {policy_name}.")
                    pass

        # Determine report status based on findings
        if findings:
            report.passed = False  # Indicate that the check failed
            report.resource_ids_status = {user['UserName']: False for user in users}  # Mark users as having issues
            report.report_metadata = {"findings": findings}  # Store findings in report metadata
            # print(f"[FAIL] Administrative privileges found for {len(findings)} policies.")
        else:
            report.passed = True  # Indicate that the check passed
            report.resource_ids_status = {user['UserName']: True for user in users}  # Mark all users as having no issues
            # print("[PASS] No administrative privileges found in inline policies.")

        return report

# The check fails if any user has an inline policy that grants full administrative privileges (i.e., Action and Resource both set to "*"). 
# It passes if no such inline policies are found for any users.






