"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from datetime import datetime, timezone
from dateutil import parser
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_avoid_root_usage(Check):
    def _get_credential_report(self, iam_client):
        """Get IAM credential report."""
        try:
            iam_client.generate_credential_report()
            response = iam_client.get_credential_report()
            return response.get('Content', b'').decode('utf-8').splitlines()
        except (ClientError, BotoCoreError):
            return []

    def _check_root_usage_status(self, user_info):
        """Check root account usage status."""
        try:
            # Extract last access times
            password_last_used = user_info[4]
            access_key_1_last_used = user_info[6]
            access_key_2_last_used = user_info[9]

            last_accessed = None

            # Find the most recent access time
            if password_last_used != "not_supported":
                last_accessed = parser.parse(password_last_used)
            elif access_key_1_last_used != "N/A":
                last_accessed = parser.parse(access_key_1_last_used)
            elif access_key_2_last_used != "N/A":
                last_accessed = parser.parse(access_key_2_last_used)

            if not last_accessed:
                return True  # No access history - Pass

            # Check if access was within last day
            days_since_accessed = (datetime.now(timezone.utc) - last_accessed).days
            return days_since_accessed > 1  # Pass if no recent access

        except (IndexError, ValueError, parser.ParserError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Default to True, will be set to False if any check fails
        
        try:
            iam_client = connection.client('iam')
            credential_report = self._get_credential_report(iam_client)

            if not credential_report:
                report.resource_ids_status['NoCredentialReport'] = False
                report.passed = False
                return report

            root_found = False
            # Process credential report (skip header row)
            for row in credential_report[1:]:
                user_info = row.split(',')
                if user_info[0] == "<root_account>":
                    root_found = True
                    status = self._check_root_usage_status(user_info)
                    report.resource_ids_status['RootAccount'] = status
                    if not status:
                        report.passed = False
                    break

            if not root_found:
                report.resource_ids_status['RootAccountNotFound'] = False
                report.passed = False

        except (ClientError, BotoCoreError):
            report.resource_ids_status['ErrorCheckingRootStatus'] = False
            report.passed = False

        return report

