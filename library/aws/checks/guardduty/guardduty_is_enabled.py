"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-25
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class guardduty_is_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.FAILED   # Default status is FAILED
        summary = "GuardDuty is not enabled" # Default summary 
        
        try:
            client = connection.client("guardduty")
            detector_ids = []
            next_token = None

            # Fetch all detectors using pagination
            while True: 
                response = client.list_detectors(NextToken=next_token) if next_token else client.list_detectors()
                detector_ids.extend(response.get("DetectorIds", []))
                next_token = response.get("NextToken")

                if not next_token:  # Break loop if no more pages
                    break

            # If no detectors exist, mark check as FAILED
            if not detector_ids:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.FAILED,
                        summary=summary
                    )
                )
                return report

            # Process each detector, if atleast one of the detector is enabled, mark check as PASSED
            for detector_id in detector_ids:
                try:
                    detector = client.get_detector(DetectorId=detector_id)
                    detector_status = detector.get("Status", "DISABLED")

                    if detector_status == "ENABLED":
                        status = CheckStatus.PASSED
                        summary = f"GuardDuty is enabled"
                    
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=status,
                            summary=summary
                        )
                    )

                except Exception as e:
                    error_message = f"Error retrieving GuardDuty detector {detector_id}: {str(e)}"
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.UNKNOWN,
                            summary=error_message,
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            error_message = f"Error connecting to GuardDuty: {str(e)}"
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=error_message,
                    exception=str(e)
                )
            )

        return report
