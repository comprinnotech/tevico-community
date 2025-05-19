"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-31
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, ResourceStatus, GeneralResource
from tevico.engine.entities.check.check import Check

class macie_auto_sensitive_data_discovery_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('macie2')
        report = CheckReport(name=__name__)
        
        try:
            response = client.get_automated_discovery_configuration()
            auto_discovery_status = response.get('status', 'DISABLED')
            
            if auto_discovery_status == 'ENABLED':
                report.status = CheckStatus.PASSED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.PASSED,
                        summary="Macie automated sensitive data discovery is enabled."
                    )
                )
            else:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary="Macie automated sensitive data discovery is disabled."
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
                    summary=f"Unexpected error while checking Macie auto-discovery: {str(e)}",
                    exception=str(e)
                )
            )
        
        return report
