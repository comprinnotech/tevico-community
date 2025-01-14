"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class iam_root_mfa_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize the report status as passed unless root MFA is found to be disabled
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Get account summary to check root user configuration
            account_summary = client.get_account_summary()
            root_mfa_devices = account_summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)

            if root_mfa_devices == 1:
                # Root MFA is enabled
                report.resource_ids_status["Root account MFA"] = True
            else:
                # Root MFA is disabled
                report.passed = False
                report.resource_ids_status["Root account MFA"] = False
        except Exception as e:
            logging.error(f"Error while checking root MFA configuration: {e}")
            report.passed = False
            report.resource_ids_status = {}

        return report
