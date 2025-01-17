"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_user_multiple_active_access_keys(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless we find multiple active access keys
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Retrieve the list of IAM users
            users = client.list_users()['Users']

            for user in users:
                username = user['UserName']
                
                # Retrieve access keys for the user
                response = client.list_access_keys(UserName=username)
                access_keys = response['AccessKeyMetadata']

                # Count active access keys
                active_keys_count = sum(1 for key in access_keys if key['Status'] == 'Active')

                if active_keys_count > 1:
                    # If the user has more than one active access key, report failure
                    report.resource_ids_status[f"User {username} has {active_keys_count} active access keys."] = False
                    report.status = ResourceStatus.FAILED
                elif active_keys_count == 1:
                    # If only one active access key exists, mark as compliant
                    report.resource_ids_status[f"User {username} has one active access key."] = True
                else:
                    # If no active access keys, mark as compliant
                    report.resource_ids_status[f"User {username} has no active access keys."] = True

        except Exception as e:
            # Handle errors such as network issues or IAM permission issues
            logging.error(f"Error while checking access keys for IAM users: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
