"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-31
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_password_policy_number(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Create an IAM client using the provided boto3 session
            client = connection.client('iam')

            # Fetch the account's IAM password policy
            account_password_policy = client.get_account_password_policy()
            password_policy = account_password_policy['PasswordPolicy']

            # Check if passwords require at least one numeric character
            require_numbers = password_policy.get('RequireNumbers', False)

            if require_numbers:
                report.status = CheckStatus.PASSED
                summary_msg = "Password policy requires at least one numeric character."
            else:
                report.status = CheckStatus.FAILED
                summary_msg = "Password policy does NOT enforce at least one numeric character."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="password_policy"),
                    status=report.status,
                    summary=summary_msg
                )
            )

        except client.exceptions.NoSuchEntityException:
            # No password policy exists
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="password_policy"),
                    status=CheckStatus.FAILED,
                    summary="No password policy found. It is recommended to enforce password policies requiring at least one numeric character."
                )
            )

        except (BotoCoreError, ClientError) as e:
            # Handle AWS API errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="password_policy"),
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
                    resource=GeneralResource(name="password_policy"),
                    status=CheckStatus.UNKNOWN,
                    summary="Unhandled exception occurred while checking the password policy.",
                    exception=str(e)
                )
            )

        return report
