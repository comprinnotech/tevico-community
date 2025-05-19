"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class inspector_ec2_scan_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED
        report.resource_ids_status = []

        #Initialize the boto3 client for Inspector2 and STS
        client = connection.client("inspector2")
        sts = connection.client("sts")

        try:
            
            account_id = sts.get_caller_identity()["Account"]

            # Call batch_get_account_status with the current account ID
            response = client.batch_get_account_status(accountIds=[account_id])
            accounts = response.get("accounts", [])
            account_status = accounts[0]
            ec2_status = account_status.get("resourceState", {}).get("ec2", {}).get("status")


            if ec2_status == "ENABLED":
                status = CheckStatus.PASSED
                summary = "Inspector EC2 standard scan is enabled."
            elif ec2_status == "DISABLED":
                status = CheckStatus.FAILED
                summary = "Inspector EC2 standard scan is not enabled."
            elif ec2_status == "SUSPENDED":
                status = CheckStatus.FAILED
                summary = "Inspector EC2 standard scan is suspended."
            else:
                status = CheckStatus.UNKNOWN
                summary = f"Inspector EC2 standard scan is in transitional state: {ec2_status}."
            
            report.status = status
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=status,
                    summary=summary
                )
            )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking Inspector EC2 scan status: {str(e)}",
                    exception=str(e)
                )
            )

        return report
