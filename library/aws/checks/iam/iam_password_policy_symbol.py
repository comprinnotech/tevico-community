"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_password_policy_symbol(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            # Fetch the current account password policy
            password_policy = client.get_account_password_policy()

            # Check if symbols are required in the password policy
            require_symbols = password_policy.get("PasswordPolicy", {}).get("RequireSymbols", False)

            if require_symbols:
                report.status = CheckStatus.PASSED
                summary = "The IAM password policy enforces the use of at least one symbol."
            else:
                report.status = CheckStatus.FAILED
                summary = "The IAM password policy does not enforce the use of at least one symbol. Update recommended."

            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAMPasswordPolicy"),
                    status=report.status,
                    summary=summary
                )
            )

        except client.exceptions.NoSuchEntityException:
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
