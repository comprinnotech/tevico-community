"""
AUTHOR: RONIT CHAUHAN 
DATE: 2024-10-11

Description: This code performs a security audit of AWS users' permissions to find any dangerous 
administrative privileges. Think of it like checking if any employees have master keys that 
give them access to everything in the building when they should only have limited access.
"""

import boto3
import logging
from botocore.exceptions import BotoCoreError, ClientError
from typing import Dict, List, Any

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

# Set up logging to track our security audit (like a security camera recording events)
logger = logging.getLogger(__name__)

class iam_customer_attached_policy_admin_privileges_found(Check):
    """
    This security check works like a security audit team that:
    1. Finds all AWS users (like employees in a building)
    2. Checks their access permissions (like checking their access cards)
    3. Reports any users who have too much access (like finding someone with a master key)
    """

    def _check_admin_privileges(self, statement: Dict[str, Any]) -> bool:
        """
        Checks if a policy gives too much power (full administrative access).
        Like checking if an access card can open every door in the building.
        """
        if statement.get('Effect') != 'Allow':
            return False

        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])

        # Check for unlimited access permissions
        if actions == "*" and resources == "*":
            return True
        if (isinstance(actions, list) and "*" in actions and 
            isinstance(resources, list) and "*" in resources):
            return True
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Main security audit function - checks all users' permissions.
        Like doing a complete security sweep of the building.
        """
        # Initialize our security audit report
        report = CheckReport(name=__name__)
        findings: List[Dict[str, Any]] = []
        resource_ids_status: Dict[str, bool] = {}
        overall_passed = True

        # Step 1: Connect to AWS Security Service
        try:
            iam_client = connection.client('iam')
            logger.info("Successfully connected to AWS security service")
        except (BotoCoreError, ClientError) as e:
            error_msg = f"Cannot connect to AWS security service: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}
            return report

        # Step 2: Get list of all AWS users
        try:
            users = iam_client.list_users().get('Users', [])
            logger.info(f"Found {len(users)} users to check")
        except (BotoCoreError, ClientError) as e:
            error_msg = f"Cannot get list of users: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}
            return report

        # Step 3: Check each user's permissions
        for user in users:
            user_name = user.get('UserName', "Unknown")
            user_status = True  # Assume user is safe until proven otherwise
            logger.info(f"Checking access permissions for user: {user_name}")

            try:
                # Get all policies attached to this user
                attached_policies = iam_client.list_attached_user_policies(
                    UserName=user_name
                ).get('AttachedPolicies', [])
                logger.info(f"Found {len(attached_policies)} policies for user {user_name}")

                # Step 4: Check each policy attached to the user
                for policy in attached_policies:
                    policy_arn = policy.get('PolicyArn', "Unknown")
                    policy_name = policy.get('PolicyName', "Unknown")

                    try:
                        # Get detailed policy information
                        policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                        
                        # Skip AWS's built-in policies
                        if policy_details['Policy']['Arn'].startswith('arn:aws:iam::aws:policy/'):
                            logger.info(f"Skipping AWS managed policy: {policy_name}")
                            continue

                        # Get the actual policy rules
                        policy_version = policy_details['Policy']['DefaultVersionId']
                        policy_document = iam_client.get_policy_version(
                            PolicyArn=policy_arn, 
                            VersionId=policy_version
                        ).get('PolicyVersion', {}).get('Document', {})

                        # Step 5: Check if policy has dangerous permissions
                        if 'Statement' in policy_document:
                            statements = policy_document['Statement']
                            if isinstance(statements, dict):
                                statements = [statements]

                            for statement in statements:
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    resources = statement.get('Resource', [])

                                    # Check for unlimited access
                                    if (actions == "*" and resources == "*") or \
                                       (isinstance(actions, list) and "*" in actions and 
                                        isinstance(resources, list) and "*" in resources):
                                        
                                        # Commented out the alert generation logic
                                        # warning_msg = (f"SECURITY ALERT: User {user_name} has "
                                        #              f"unlimited access through policy {policy_name}")
                                        # logger.warning(warning_msg)
                                        
                                        findings.append({
                                            "resource_id": user_name,
                                            "status": "FAIL",
                                            "status_extended": "User has unlimited access through policy"
                                        })
                                        resource_ids_status[user_name] = False
                                        overall_passed = False
                                        user_status = False
                                        break

                    except (BotoCoreError, ClientError) as e:
                        error_msg = f"Error checking policy {policy_name}: {str(e)}"
                        logger.error(error_msg)
                        findings.append({
                            "resource_id": user_name,
                            "status": "ERROR",
                            "status_extended": error_msg
                        })
                        continue

                # Step 6: Record results for this user
                if user_status:
                    success_msg = f"User {user_name} has appropriate access levels"
                    logger.info(success_msg)
                    findings.append({
                        "resource_id": user_name,
                        "status": "PASS",
                        "status_extended": success_msg
                    })
                    resource_ids_status[user_name] = True

            except (BotoCoreError, ClientError) as e:
                error_msg = f"Error checking user {user_name}: {str(e)}"
                logger.error(error_msg)
                findings.append({
                    "resource_id": user_name,
                    "status": "ERROR",
                    "status_extended": error_msg
                })
                resource_ids_status[user_name] = False
                overall_passed = False

        # Step 7: Prepare final security report
        try:
            report.passed = overall_passed
            report.resource_ids_status = resource_ids_status
            report.report_metadata = {"findings": findings}
            logger.info("Security audit completed successfully")
        except Exception as e:
            error_msg = f"Error creating final report: {str(e)}"
            logger.error(error_msg)
            report.passed = False
            report.report_metadata = {"error": error_msg}

        return report


    
# The check will **pass** if no attached custom managed policies grant full administrative privileges (i.e., no policies have both `"Action": "*"` and `"Resource": "*"`).
# It will **fail** if any custom managed policy grants full administrative privileges to any user.
