"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_customer_unattached_policy_admin_privileges_found(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        # Initialize the IAM client
        iam_client = connection.client('iam')

        findings = []

        # Fetch all policies
        policies = iam_client.list_policies(Scope='Local')['Policies']

        for policy in policies:
            policy_arn = policy['Arn']

            # Check if the policy is custom and not attached to any user, group, or role
            if policy['AttachmentCount'] == 0 and policy['DefaultVersionId'] != 'aws-managed':
                # Fetch policy details
                policy_details = iam_client.get_policy(PolicyArn=policy_arn)

                # Get the policy document
                policy_version = policy_details['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

                # Initialize report for the policy
                report_entry = {
                    "resource_arn": policy_arn,
                    "resource_id": policy['PolicyName'],
                    "resource_tags": policy.get('Tags', {}),
                    "status": "PASS",
                    "status_extended": f"Custom policy {policy['PolicyName']} is unattached and does not allow '*:*' administrative privileges."
                }

                # Check if the policy grants full administrative privileges
                if 'Statement' in policy_document:
                    if type(policy_document['Statement']) == dict:
                        policy_document['Statement'] = [policy_document['Statement']]
                    
                    for statement in policy_document['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            # Check if actions allow all actions and resources ('*:*' means admin privileges)
                            if actions == "*" and resources == "*":
                                report_entry['status'] = "FAIL"
                                report_entry['status_extended'] = f"Custom policy {policy['PolicyName']} is unattached and allows '*:*' administrative privileges."
                                break  # Stop after detecting full admin privileges
                            elif isinstance(actions, list) and "*" in actions and isinstance(resources, list) and "*" in resources:
                                report_entry['status'] = "FAIL"
                                report_entry['status_extended'] = f"Custom policy {policy['PolicyName']} is unattached and allows '*:*' administrative privileges."
                                break  # Stop after detecting full admin privileges
                
                findings.append(report_entry)

        # Determine report status based on findings
        if all(entry['status'] == "PASS" for entry in findings): # Indicate that the check passed only if all reports are "PASS"
            report.status = ResourceStatus.PASSED
        else:
            report.status = ResourceStatus.FAILED

        report.resource_ids_status = {entry['resource_id']: (entry['status'] == "PASS") for entry in findings}  # Mark policies as having issues or not
        report.report_metadata = {"findings": findings}  # Store findings in report metadata

        return report
    
    #The code fails if any unattached custom policy is found that allows full administrative privileges (i.e., has both "Action": "*" and "Resource": "*"), indicating a security risk.
    #The code passes if all unattached custom policies do not grant full administrative privileges, ensuring that no excessive permissions are left unchecked.
