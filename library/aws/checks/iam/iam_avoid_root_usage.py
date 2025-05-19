"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import time
import boto3
from datetime import datetime, timezone
from dateutil import parser
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

# Define the maximum allowed number of days for root access
MAX_ACCESS_DAYS = 7

class iam_avoid_root_usage(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        report.resource_ids_status = []

        try:
            # Wait for the credential report to be ready
            for _ in range(5):  # Retry up to 10 times (approx 30 seconds max wait time)
                response = client.generate_credential_report()
                state = response["State"]
                if state == "COMPLETE":
                    break
                time.sleep(3)  # Wait before retrying
            else:
                raise Exception("Credential report generation timed out.")

            # Retrieve the credential report
            response = client.get_credential_report()["Content"]
            decoded_report = response.decode("utf-8").splitlines()

            # Extract header dynamically
            headers = decoded_report[0].split(',')
            rows = decoded_report[1:]

            # Get column indexes safely
            password_last_used_idx = headers.index("password_last_used") if "password_last_used" in headers else None
            access_key_1_last_used_idx = headers.index("access_key_1_last_used") if "access_key_1_last_used" in headers else None
            access_key_2_last_used_idx = headers.index("access_key_2_last_used") if "access_key_2_last_used" in headers else None

            for row in rows:
                user_info = row.split(',')

                if user_info[0] == "<root_account>":
                    # Get values safely using indexes
                    password_last_used = user_info[password_last_used_idx].strip() if password_last_used_idx is not None else "no_information"
                    access_key_1_last_used = user_info[access_key_1_last_used_idx].strip() if access_key_1_last_used_idx is not None else "no_information"
                    access_key_2_last_used = user_info[access_key_2_last_used_idx].strip() if access_key_2_last_used_idx is not None else "no_information"

                    last_accessed = None
                    timestamp_values = [password_last_used, access_key_1_last_used, access_key_2_last_used]

                    # Find the most recent valid access timestamp
                    for timestamp in timestamp_values:
                        if timestamp not in ["not_supported", "no_information", "N/A"]:
                            try:
                                last_accessed = parser.parse(timestamp)
                                break  # Use the first valid timestamp found
                            except ValueError:
                                continue  # Ignore invalid formats

                    if last_accessed:
                        days_since_accessed = (datetime.now(timezone.utc) - last_accessed).days

                        # Check if root was accessed within the restricted period
                        if days_since_accessed <= MAX_ACCESS_DAYS:
                            report.status = CheckStatus.FAILED
                            summary = f"Root account was accessed {days_since_accessed} days ago. Immediate action recommended."
                        else:
                            report.status = CheckStatus.PASSED
                            summary = f"Root account last accessed {days_since_accessed} days ago."

                    else:
                        report.status = CheckStatus.SKIPPED
                        summary = "No valid last access timestamp found for the root account."

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name="RootAccount"),
                            status=report.status,
                            summary=summary
                        )
                    )
                    break  # Stop processing after the root account

        except (BotoCoreError, ClientError, Exception) as e:
            # Set status to UNKNOWN when API call fails
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="RootAccount"),
                    status=CheckStatus.UNKNOWN,
                    summary="IAM API request failed. Unable to determine root account usage.",
                    exception=str(e)
                )
            )

        return report
