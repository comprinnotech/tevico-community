"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import botocore.exceptions
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, ResourceStatus, GeneralResource
from tevico.engine.entities.check.check import Check


class iam_user_multiple_active_access_keys(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        resource = GeneralResource(name="AWS IAM")  # Default resource for error handling

        try:
            client = connection.client("iam")
            paginator = client.get_paginator("list_users")
            
            users = []
            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            # Handle no IAM users scenario
            if not users:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=resource,
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No IAM users found."
                    )
                )
                return report

            has_failed_users = False  # Track if any user fails the access key check

            for user in users:
                username = user["UserName"]
                arn = user["Arn"]  # IAM User ARN for proper resource tracking
                resource = AwsResource(arn=arn)

                # Step 2: Retrieve Access Keys for the User with Pagination
                try:
                    key_paginator = client.get_paginator("list_access_keys")
                    access_keys = []
                    for key_page in key_paginator.paginate(UserName=username):
                        access_keys.extend(key_page.get("AccessKeyMetadata", []))
                except botocore.exceptions.ClientError as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"AWS API error occurred while retrieving access keys for {username}.",
                            exception=str(e)
                        )
                    )
                    continue  # Skip this user and continue with others

                # Step 3: Count Active Access Keys
                active_keys_count = sum(1 for key in access_keys if key["Status"] == "Active")

                # Determine status based on active keys count
                if active_keys_count > 1:
                    has_failed_users = True
                    status = CheckStatus.FAILED
                else:
                    status = CheckStatus.PASSED

                # Append the status of this user
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=resource,
                        status=status,
                        summary=f"Number of active access key(s) for {username}: {active_keys_count}."
                    )
                )

            # Set overall status if any user failed the check
            if has_failed_users:
                report.status = CheckStatus.FAILED

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=resource,
                    status=CheckStatus.UNKNOWN,
                    summary="Unknown error occurred while checking IAM access keys.",
                    exception=str(e)
                )
            )

        return report
