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


class iam_rotate_access_keys_90_days(Check):

    def execute(self, connection: boto3.Session, maximum_key_age: int = 90) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless we find non-compliant keys
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

                for key in access_keys:
                    key_id = key['AccessKeyId']
                    status = key['Status']
                    create_date = key['CreateDate']

                    # Calculate the age of the access key
                    days_since_created = (datetime.datetime.now(pytz.utc) - create_date).days

                    if status == 'Active' and days_since_created > maximum_key_age:
                        # Key is active and older than the maximum allowed age
                        report.resource_ids_status[f"User {username}, Access Key {key_id} is older than {maximum_key_age} days."] = False
                        report.status = ResourceStatus.FAILED
                    elif status == 'Active':
                        # Key is active and compliant
                        report.resource_ids_status[f"User {username}, Access Key {key_id} is compliant."] = True
                    else:
                        # Key is inactive (not checked for rotation)
                        report.resource_ids_status[f"User {username}, Access Key {key_id} is inactive."] = True

        except Exception as e:
            # Handle errors such as network issues or IAM permission issues
            logging.error(f"Error while checking access key rotation for IAM users: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["Error occurred while checking access key rotation"] = False

        return report
