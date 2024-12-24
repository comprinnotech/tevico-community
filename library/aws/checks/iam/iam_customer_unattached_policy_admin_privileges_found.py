"""
AUTHOR: RONIT CHAUHAN
DATE: 2024-10-11

Description: This code acts like a security guard checking for potentially dangerous access cards (AWS policies) 
that aren't being used but still have full access to everything. It's similar to finding master keys 
that aren't assigned to anyone but could be dangerous if they fall into the wrong hands.
"""

import boto3
import logging
from botocore.exceptions import BotoCoreError, ClientError
from typing import Dict, List, Any

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging to track what our code is doing (like a security camera recording events)
logger = logging.getLogger(__name__)

class iam_customer_unattached_policy_admin_privileges_found(Check):
    """
    This security check does three main things:
    1. Finds all custom-made AWS policies that aren't attached to anyone
    2. Checks if these unattached policies have dangerous "full access" permissions
    3. Reports any risky policies that could be security threats
    """

    def _create_policy_report_entry(self, policy: Dict[str, Any], status: str, message: str) -> Dict[str, Any]:
        """
        Creates a standardized security report entry for each policy we check.
        Like filling out a security incident report form.
        """
        return {
            "resource_arn": policy['Arn'],  # Policy's unique ID
            "resource_id": policy['PolicyName'],  # Policy's name
            "resource_tags": policy.get('Tags', {}),  # Any labels attached to the policy
            "status": status,  # Whether the policy passed or failed our security check
            "status_extended": message  # Detailed explanation of what we found
        }

    def _check_admin_privileges(self, policy_document: Dict[str, Any]) -> bool:
        """
        Examines a policy to see if it has dangerous full-access permissions.
        Like checking if a key can open all doors in the building.
        """
        if 'Statement' not in policy_document:
            return False

        statements = policy_document['Statement']
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                # Check for full access permissions (like a master key)
                if actions == "*" and resources == "*":
                    return True
                if (isinstance(actions, list) and "*" in actions and 
                    isinstance(resources, list) and "*" in resources):
                    return True

        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main security check function - like doing a complete security audit of all access cards.
        """
        # Start our security report
        report = CheckReport(name=__name__)
        findings: List[Dict[str, Any]] = []

        # Step 1: Connect to AWS IAM (like accessing the security system)
        try:
            iam_client = connection.client('iam')
            logger.info("Successfully connected to AWS IAM service")
        except (BotoCoreError, ClientError) as e:
            error_msg = f"Cannot connect to AWS security service: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}
            return report

        # Step 2: Get list of all custom policies
        try:
            policies = iam_client.list_policies(Scope='Local')['Policies']
            logger.info(f"Found {len(policies)} custom policies to check")
        except (BotoCoreError, ClientError) as e:
            error_msg = f"Cannot get list of policies: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}
            return report

        # Step 3: Check each policy for security risks
        for policy in policies:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']

            # Only check policies that aren't attached to anyone
            if policy['AttachmentCount'] == 0 and policy.get('DefaultVersionId') != 'aws-managed':
                logger.info(f"Checking unattached policy: {policy_name}")

                try:
                    # Get detailed policy information
                    policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                    policy_version = policy_details['Policy']['DefaultVersionId']
                    policy_document = iam_client.get_policy_version(
                        PolicyArn=policy_arn, 
                        VersionId=policy_version
                    )['PolicyVersion']['Document']

                    # Check if policy has dangerous permissions
                    if self._check_admin_privileges(policy_document):
                        findings.append(self._create_policy_report_entry(
                            policy,
                            "FAIL",
                            f"WARNING: Policy {policy_name} is not being used but has dangerous full-access permissions"
                        ))
                        logger.warning(f"Found risky policy: {policy_name}")
                    else:
                        findings.append(self._create_policy_report_entry(
                            policy,
                            "PASS",
                            f"Policy {policy_name} is safe - no dangerous permissions found"
                        ))
                        logger.info(f"Policy {policy_name} passed security check")

                except (BotoCoreError, ClientError) as e:
                    error_msg = f"Cannot check policy {policy_name}: {str(e)}"
                    logger.error(error_msg)
                    findings.append(self._create_policy_report_entry(
                        policy,
                        "ERROR",
                        error_msg
                    ))

        # Step 4: Create final security report
        try:
            # Mark each policy as safe (PASS) or risky (FAIL)
            report.resource_ids_status = {
                entry['resource_id']: (entry['status'] == "PASS") 
                for entry in findings
            }
            report.report_metadata = {"findings": findings}
            
            # Overall check passes only if all policies are safe
            report.passed = all(entry['status'] == "PASS" for entry in findings)
            
            logger.info(f"Security check completed - Found {len(findings)} policies to review")
            
        except Exception as e:
            error_msg = f"Error creating final report: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}

        return report

    
    #The code fails if any unattached custom policy is found that allows full administrative privileges (i.e., has both "Action": "*" and "Resource": "*"), indicating a security risk.
    #The code passes if all unattached custom policies do not grant full administrative privileges, ensuring that no excessive permissions are left unchecked.
