"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""


import boto3
import logging
import datetime
import pytz
from dateutil import parser

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_avoid_root_usage(Check):

    def execute(self, connection: boto3.Session, maximum_access_days: int = 90) -> CheckReport:
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as 'Passed' unless we find the root user was accessed recently
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Get the IAM account information
            account_info = client.get_account_summary()
            root_user = account_info['SummaryMap'].get('AccountAccessKeysPresent', 0)

            # Check if root user has access keys or password and was recently used
            if root_user > 0:
                user = client.get_user(UserName="root")['User']
                last_password_used = user.get('PasswordLastUsed', 'no_information')
                access_key_1_last_used = user.get('AccessKey1LastUsedDate', 'N/A')
                access_key_2_last_used = user.get('AccessKey2LastUsedDate', 'N/A')

                days_since_accessed = None
                if last_password_used != 'no_information':
                    days_since_accessed = (datetime.datetime.now(pytz.utc) - parser.parse(last_password_used)).days
                elif access_key_1_last_used != 'N/A':
                    days_since_accessed = (datetime.datetime.now(pytz.utc) - parser.parse(access_key_1_last_used)).days
                elif access_key_2_last_used != 'N/A':
                    days_since_accessed = (datetime.datetime.now(pytz.utc) - parser.parse(access_key_2_last_used)).days

                # If root user was accessed within the maximum access days threshold
                if days_since_accessed is not None and days_since_accessed <= maximum_access_days:
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[f"Root user recently accessed. [ Root user in the account was last accessed {days_since_accessed} days ago.]"] = False
                else:
                    report.status = ResourceStatus.PASSED
                    report.resource_ids_status[f"Root user not recently accessed. [ Root user in the account wasn't accessed in the last {maximum_access_days} days.]"] = True
            else:
                report.status = ResourceStatus.PASSED
                report.resource_ids_status["Root user does not have access keys."] = True

        except Exception as e:
            # Handle errors
            logging.error(f"Error while checking root user access: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
