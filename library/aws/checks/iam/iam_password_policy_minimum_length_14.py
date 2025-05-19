"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-1-31
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_password_policy_minimum_length_14(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Create an IAM client using the provided boto3 session
            client = connection.client('iam')

            # Fetch the account's IAM password policy
            account_password_policy = client.get_account_password_policy()
            password_policy = account_password_policy['PasswordPolicy']

            # Get the 'MinimumPasswordLength' setting from the password policy
            minimum_password_length = password_policy.get('MinimumPasswordLength', 0)

            if minimum_password_length >= 14:
                report.status = CheckStatus.PASSED
                summary_msg = "Password policy enforces at least 14 characters."
            else:
                report.status = CheckStatus.FAILED
                summary_msg = f"Password policy requires only {minimum_password_length} characters. Minimum should be 14."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='password_policy'),
                    status=report.status,
                    summary=summary_msg
                )
            )

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='password_policy'),
                    status=CheckStatus.FAILED,
                    summary="No password policy found. It is recommended to enforce a strong password policy."
                )
            )

        except (BotoCoreError, ClientError) as e:
            # Handle AWS API errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='password_policy'),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while fetching the password policy.",
                    exception=str(e)
                )
            )

        except Exception as e:
            # Catch-all for unexpected errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name='password_policy'),
                    status=CheckStatus.UNKNOWN,
                    summary="Unhandled exception occurred while checking the password policy.",
                    exception=str(e)
                )
            )

        return report
