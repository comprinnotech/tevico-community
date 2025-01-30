"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_user_mfa_enabled_console_access(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            users = client.list_users()['Users']

            for user in users:
                username = user['UserName']
                
                # First check if user has console access
                try:
                    # get_login_profile raises NoSuchEntity if user has no console access
                    client.get_login_profile(UserName=username)
                    
                    has_console_access = True
                except client.exceptions.NoSuchEntityException:
                    # User doesn't have console access, skip MFA check
                    report.resource_ids_status[f"User: {username} does not have console access"] = True
                    continue
                except Exception as e:
                    logging.error(f"Error checking login profile for user {username}: {e}")
                    continue

                # Only check MFA if user has console access
                if has_console_access:
                    response = client.list_mfa_devices(UserName=username)
                    mfa_devices = response['MFADevices']

                    if mfa_devices:
                        for mfa_device in mfa_devices:
                            if mfa_device['EnableDate']:
                                report.resource_ids_status[f"User: {username} has console access with MFA enabled"] = True
                    else:
                        report.resource_ids_status[f"User: {username} has console access but no MFA enabled"] = False
                        report.status = ResourceStatus.FAILED

        except Exception as e:
            logging.error(f"Error while checking MFA for IAM users: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
