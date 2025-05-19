"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_password_policy_uppercase(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            # Fetch the current account password policy
            password_policy = client.get_account_password_policy()

            # Check if uppercase letters are required in the password policy
            require_uppercase = password_policy.get("PasswordPolicy", {}).get("RequireUppercaseCharacters", False)

            if require_uppercase:
                report.status = CheckStatus.PASSED
                summary = "The IAM password policy enforces the use of at least one uppercase letter."
            else:
                report.status = CheckStatus.FAILED
                summary = "The IAM password policy does not enforce the use of at least one uppercase letter. Update recommended."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAMPasswordPolicy"),
                    status=report.status,
                    summary=summary
                )
            )

        except client.exceptions.NoSuchEntityException:
            # If no custom password policy exists, fail the check
            report.status = CheckStatus.FAILED
            summary = "Default IAM password policy is set. Custom policy required."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAMPasswordPolicy"),
                    status=CheckStatus.FAILED,
                    summary=summary
                )
            )

        except (BotoCoreError, ClientError) as e:
            # If the API call fails, mark as UNKNOWN
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAMPasswordPolicy"),
                    status=CheckStatus.UNKNOWN,
                    summary="Failed to retrieve IAM password policy.",
                    exception=str(e)
                )
            )

        return report
