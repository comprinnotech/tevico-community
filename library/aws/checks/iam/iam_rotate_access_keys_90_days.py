"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""


import boto3
from botocore.exceptions import ClientError, BotoCoreError
from datetime import datetime, timedelta, timezone
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_rotate_access_keys_90_days(Check):
    def _list_users(self, client):
        try:
            return client.list_users().get('Users', [])
        except (ClientError, BotoCoreError):
            return []

    def _list_access_keys(self, client, username):
        try:
            return client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
        except (ClientError, BotoCoreError):
            return []

    def _check_key_age(self, key, ninety_days_ago):
        if key['Status'] == 'Active':
            key_age = datetime.now(timezone.utc) - key['CreateDate']
            return key_age.days >= 90
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        client = connection.client('iam')

        try:
            current_time = datetime.now(timezone.utc)
            ninety_days_ago = current_time - timedelta(days=90)

            users = self._list_users(client)
            if not users:
                report.passed = False
                return report

            for user in users:
                try:
                    username = user['UserName']
                    access_keys = self._list_access_keys(client, username)

                    if not access_keys:
                        report.resource_ids_status[username] = True
                        continue

                    has_old_key = False
                    for key in access_keys:
                        if self._check_key_age(key, ninety_days_ago):
                            has_old_key = True
                            break

                    report.resource_ids_status[username] = not has_old_key
                    if has_old_key:
                        report.passed = False

                except KeyError:
                    report.passed = False
                    return report

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        return report
