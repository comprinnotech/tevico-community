"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import datetime

from tevico.engine.entities.report.check_model import AwsResource, CheckException, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

# Set maximum key age to 90 days (fixed)
MAX_KEY_AGE = 90

class iam_rotate_access_keys_90_days(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('iam')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []
        
        try:
            try:
                paginator = client.get_paginator('list_users')
                users = []
                for page in paginator.paginate():
                    users.extend(page.get('Users', []))
            except Exception as e:
                report.status = CheckStatus.UNKNOWN
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="IAM Users"),
                        status=CheckStatus.UNKNOWN,
                        summary="Failed to retrieve IAM users.",
                        exception=str(e)
                    )
                )
                return report  # Exit early if we can't get users

            if not users:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="IAM"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No IAM users found."
                    )
                )
                return report

            for user in users:
                username = user['UserName']
                arn = user['Arn']
                resource = AwsResource(arn=arn)

                try:
                    paginator = client.get_paginator('list_access_keys')
                    access_keys = []
                    
                    for page in paginator.paginate(UserName=username):
                        access_keys.extend(page.get('AccessKeyMetadata', []))

                    if not access_keys:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=resource,
                                status=CheckStatus.NOT_APPLICABLE,
                                summary=f"No access keys found for user {username}."
                            )
                        )
                        continue

                    for key in access_keys:
                        key_id = key['AccessKeyId']
                        status = key['Status']
                        create_date = key.get('CreateDate')

                        if not create_date:
                            continue  # Skip if CreateDate is missing

                        # Ensure time zone consistency
                        days_since_created = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
                        
                        # Masking the key_id for security reasons, Only show the first 4 and last 3 characters
                        masked_key_id = key_id[:4] + "****" + key_id[-3:]
                        if status == 'Inactive':
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.PASSED,
                                    summary=f"Access Key {masked_key_id} is inactive."
                                )
                            )
                        elif days_since_created > MAX_KEY_AGE:
                            # Key is outdated
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.FAILED,
                                    summary=f"Access Key {masked_key_id} is {status} but older than {MAX_KEY_AGE} days ({days_since_created} days old)."
                                )
                            )
                            report.status = CheckStatus.FAILED
                        else:
                            # Key is compliant
                            report.resource_ids_status.append(
                                ResourceStatus(
                                    resource=resource,
                                    status=CheckStatus.PASSED,
                                    summary=f"Access Key {masked_key_id} is {status} and compliant ({days_since_created} days old)."
                                )
                            )
                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking access keys for user {username}.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

        except Exception as e:
            report.status = CheckStatus.UNKNOWN  # Set status to UNKNOWN on API failure
            report.report_metadata = {"error": str(e)}
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="IAM"),
                    status=CheckStatus.UNKNOWN,
                    summary="Error occurred while checking access key rotation.",
                    exception=str(e)
                )
            )
            
        return report
