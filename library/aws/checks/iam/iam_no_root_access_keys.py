"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-14
"""

import boto3
import time
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class iam_no_root_access_keys(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        report.resource_ids_status = []

        try:
            
            # Wait for the credential report to be ready
            for _ in range(10):  # Retry up to 10 times (approx 30 seconds max wait time)
                response = client.generate_credential_report()
                state = response["State"]
                if state == "COMPLETE":
                    break
                time.sleep(3)  # Wait before retrying
            else:
                raise ValueError("Credential report generation timed out.")

            # Step 2: Retrieve the credential report
            response = client.get_credential_report()["Content"]
            decoded_report = response.decode("utf-8").splitlines()

            # Step 3: Validate and parse the credential report
            if len(decoded_report) < 2:
                raise ValueError("Credential report is empty or invalid.")

            headers = decoded_report[0].split(',')
            rows = decoded_report[1:]

            access_key_1_active_idx = headers.index("access_key_1_active") if "access_key_1_active" in headers else None
            access_key_2_active_idx = headers.index("access_key_2_active") if "access_key_2_active" in headers else None

            for row in rows:
                user_info = row.split(',')

                if user_info[0] == "<root_account>":
                    access_key_1_active = user_info[access_key_1_active_idx].strip().lower() if access_key_1_active_idx is not None else "false"
                    access_key_2_active = user_info[access_key_2_active_idx].strip().lower() if access_key_2_active_idx is not None else "false"

                    if access_key_1_active == "true" or access_key_2_active == "true":
                        report.status = CheckStatus.FAILED
                        summary = "Root account has active access keys. Immediate removal is recommended."
                    else:
                        report.status = CheckStatus.PASSED
                        summary = "Root account has no active access keys."

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name="RootAccount"),
                            status=report.status,
                            summary=summary
                        )
                    )
                    break  # Stop processing after the root account

        except (BotoCoreError, ClientError) as e:
            # Set status to UNKNOWN when API call fails
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="RootAccount"),
                    status=CheckStatus.UNKNOWN,
                    summary="IAM API request failed. Unable to verify root access keys.",
                    exception=str(e)
                )
            )

        return report
