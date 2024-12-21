"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-16
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError

class guardduty_is_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            available_regions = connection.get_available_regions('guardduty')

            for region in available_regions:
                try:
                    regional_client = connection.client('guardduty', region_name=region)
                    detectors = regional_client.list_detectors()
                    resource_key = region

                    if not detectors.get('DetectorIds', []):
                        report.passed = False
                        report.resource_ids_status[resource_key] = False
                        continue

                    for detector_id in detectors['DetectorIds']:
                        try:
                            detector = regional_client.get_detector(DetectorId=detector_id)
                            if detector.get('Status') is None or not detector.get('Status'):
                                report.resource_ids_status[resource_key] = False
                                report.passed = False
                            else:
                                report.resource_ids_status[resource_key] = True
                        except ClientError:
                            report.resource_ids_status[resource_key] = False
                            report.passed = False

                except ClientError:
                    report.resource_ids_status[region] = False
                    report.passed = False

        except Exception:
            report.passed = False

        return report

