"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-31
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class macie_status_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("macie2")
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default status is PASSED
        report.resource_ids_status = []
        
        try:
            response = client.get_macie_session()
            macie_status = response.get("status", "DISABLED")
            
            if macie_status == "ENABLED":
                report.status = CheckStatus.PASSED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.PASSED,
                        summary="Amazon Macie is enabled."
                    )
                )
            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="Amazon Macie activities are paused or suspended."
                    )
                )
        
        except client.exceptions.AccessDeniedException:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Access denied while checking Amazon Macie status."
                )
            )
        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Unexpected error: {str(e)}",
                    exception=str(e)
                )
            )
        
        return report
