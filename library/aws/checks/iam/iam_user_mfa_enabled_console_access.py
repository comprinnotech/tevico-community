"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_user_mfa_enabled_console_access(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless we find non-compliance
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Retrieve the list of IAM users
            users = client.list_users()['Users']

            for user in users:
                username = user['UserName']

                # Check if the user has console access
                response = client.list_mfa_devices(UserName=username)
                mfa_devices = response['MFADevices']

                if mfa_devices:
                    # If the user has MFA enabled, check if they have console access
                    for mfa_device in mfa_devices:
                        if mfa_device['EnableDate']:
                            # User has MFA enabled and console access
                            report.resource_ids_status[f"User {username} has MFA enabled and console access"] = True
                else:
                    # User does not have MFA enabled
                    report.resource_ids_status[f"User {username} does not have MFA enabled for console access"] = False
                    report.passed = False

        except Exception as e:
            # Handle errors such as network issues or IAM permission issues
            logging.error(f"Error while checking MFA for IAM users: {e}")
            report.passed = False
            report.resource_ids_status = {}

        return report
