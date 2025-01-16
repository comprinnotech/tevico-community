"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-1-7
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_inline_policy_admin_privileges_found(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Check IAM users, groups, and roles for inline policies with administrative privileges.

        :param connection: boto3 session
        :return: CheckReport
        """
        # Initialize IAM client
        client = connection.client('iam')

        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED  # Default to passed until an admin inline policy is found
        report.resource_ids_status = {}

        def has_admin_privileges(policy_document):
            """Check if the policy document grants admin privileges."""
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if (
                    statement.get('Effect') == 'Allow' and
                    statement.get('Action') == '*' and
                    statement.get('Resource') == '*'
                ):
                    return True
            return False

        def process_entities(entity_type, list_func, policy_list_func, policy_get_func, name_key):
            """
            Generic function to process users, groups, or roles for inline policies.

            :param entity_type: Entity type ('User', 'Group', 'Role')
            :param list_func: Function to list entities
            :param policy_list_func: Function to list policies for the entity
            :param policy_get_func: Function to get a policy document
            :param name_key: Key to extract the entity name
            """
            try:
                paginator = client.get_paginator(list_func)
                for page in paginator.paginate():
                    for entity in page[entity_type + 's']:
                        entity_name = entity[name_key]
                        failed_policies = []  # List to store failed policy names

                        try:
                            policies = client.__getattribute__(policy_list_func)(
                                **{entity_type + 'Name': entity_name}
                            )['PolicyNames']

                            # Check each policy for admin privileges
                            for policy_name in policies:
                                policy_document = client.__getattribute__(policy_get_func)(
                                    **{entity_type + 'Name': entity_name, 'PolicyName': policy_name}
                                )['PolicyDocument']

                                if has_admin_privileges(policy_document):
                                    # Add the failed policy name to the list
                                    failed_policies.append(policy_name)
                                    report.status = ResourceStatus.FAILED

                            # If there were failed policies, store them as a comma-separated list
                            if failed_policies:
                                # Store the status as False and append policy names
                                report.resource_ids_status[f"{entity_type}::{entity_name} has inline policy {', '.join(failed_policies)} with full administrative privileges." ] = False
                                
                            # If no failed policies, store the success status as True
                            elif f"{entity_type}::{entity_name}" not in report.resource_ids_status:
                                report.resource_ids_status[f"{entity_type}::{entity_name} has not any inline policy with full administrative privileges."] = True

                        except (BotoCoreError, ClientError):
                            # Mark as fail on error and add to the status
                            report.status = ResourceStatus.FAILED
                            report.resource_ids_status[f"{entity_type}::{entity_name}"] = False
            except (BotoCoreError, ClientError):
                report.status = ResourceStatus.FAILED

        # Process IAM users, groups, and roles
        process_entities(
            entity_type='User',
            list_func='list_users',
            policy_list_func='list_user_policies',
            policy_get_func='get_user_policy',
            name_key='UserName'
        )
        # Uncomment and extend to process groups and roles
        # process_entities(
        #     entity_type='Group',
        #     list_func='list_groups',
        #     policy_list_func='list_group_policies',
        #     policy_get_func='get_group_policy',
        #     name_key='GroupName'
        # )
        # process_entities(
        #     entity_type='Role',
        #     list_func='list_roles',
        #     policy_list_func='list_role_policies',
        #     policy_get_func='get_role_policy',
        #     name_key='RoleName'
        # )
        # If any failure was found, the check should fail
        if any(status is False for status in report.resource_ids_status.values()):
            report.status = ResourceStatus.FAILED  # Ensure this is a boolean

        return report
 