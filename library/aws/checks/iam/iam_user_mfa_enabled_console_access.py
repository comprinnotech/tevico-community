"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import botocore.exceptions
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, ResourceStatus, GeneralResource
from tevico.engine.entities.check.check import Check


class iam_user_mfa_enabled_console_access(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            paginator = client.get_paginator('list_users')
            users = []
            for page in paginator.paginate():
                users.extend(page.get('Users', []))

            if not users:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="AWS IAM"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No IAM users found."
                    )
                )
                return report

            for user in users:
                username = user['UserName']
                arn = user['Arn']
                resource = AwsResource(arn=arn)

                # Step 1: Check if the user has console access
                try:
                    client.get_login_profile(UserName=username)
                except client.exceptions.NoSuchEntityException:
                    # User does not have console access, skip MFA check
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.NOT_APPLICABLE,
                            summary=f"User {username} does not have console access."
                        )
                    )
                    continue
                except botocore.exceptions.ClientError as e:
                    if "ThrottlingException" in str(e):
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary="AWS API throttling occurred while checking console access.",
                                exception=str(e)
                            )
                        )
                        continue  # Skip user and continue processing others
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary="Error checking console access.",
                            exception=str(e)
                        )
                    )
                    continue

                # Step 2: Check if MFA is enabled for console-access users
                try:
                    paginator = client.get_paginator('list_mfa_devices')
                    mfa_devices = []
                    for page in paginator.paginate(UserName=username):
                        mfa_devices.extend(page.get('MFADevices', []))

                    if mfa_devices:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.PASSED,
                                summary=f"Console access is enabled for {username} with MFA configured."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.FAILED,
                                summary=f"Console access is enabled for {username}, but MFA is not configured."
                            )
                        )

                except botocore.exceptions.ClientError as e:
                    if "ThrottlingException" in str(e):
                        report.status = CheckStatus.UNKNOWN
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.UNKNOWN,
                                summary="AWS API throttling occurred while checking MFA configuration.",
                                exception=str(e)
                            )
                        )
                        continue
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary="Error checking MFA configuration.",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="AWS IAM"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error while checking MFA for IAM users.",
                    exception=str(e)
                )
            )

        return report
