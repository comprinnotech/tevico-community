"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-07
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class iam_password_policy_lowercase(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Check if the IAM password policy requires at least one lowercase letter.

        :param connection: boto3 session
        :return: CheckReport
        """
        # Initialize IAM client
        client = connection.client('iam')

        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to passed
        report.resource_ids_status = []

        try:
            policy = client.get_account_password_policy()['PasswordPolicy']
            requires_lowercase = policy.get('RequireLowercaseCharacters', False)

            if requires_lowercase:
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="Password Policy"),
                        status=CheckStatus.PASSED,
                        summary="The IAM password policy enforces the use of at least one lowercase letter."
                    )
                )
            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="Password Policy"),
                        status=CheckStatus.FAILED,
                        summary="The IAM password policy does not enforce the use of at least one lowercase letter."
                    )
                )

        except client.exceptions.NoSuchEntityException:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Password Policy"),
                    status=CheckStatus.FAILED,
                    summary="No custom IAM password policy is configured. It is recommended to define one."
                )
            )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="Password Policy"),
                    status=CheckStatus.UNKNOWN,
                    summary="An error occurred while retrieving the IAM password policy.",
                    exception=str(e)
                )
            )

        return report
