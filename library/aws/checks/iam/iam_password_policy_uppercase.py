"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_password_policy_uppercase(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize IAM client
        client = connection.client('iam')
        report = CheckReport(name=__name__)

        # Initialize report status as passed unless the policy is non-compliant
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Retrieve the account password policy
            response = client.get_account_password_policy()
            password_policy = response.get('PasswordPolicy', {})

            # Check if the password policy requires uppercase letters
            requires_uppercase = password_policy.get('RequireUppercaseCharacters', False)

            if requires_uppercase:
                # Password policy is compliant
                report.resource_ids_status["Password policy requires uppercase characters"] = True
            else:
                # Password policy is not compliant
                report.status = ResourceStatus.FAILED
                report.resource_ids_status["Password policy requires uppercase characters"] = False

        except client.exceptions.NoSuchEntityException:
            # Handle cases where no password policy is set
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["Password policy exists"] = False
        except Exception as e:
            # Handle unexpected errors
            logging.error(f"Error while checking password policy: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
