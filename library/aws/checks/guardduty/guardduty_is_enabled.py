"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-16
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError


class guardduty_is_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            available_regions = connection.get_available_regions('guardduty')

            def check_region(region):
                regional_client = connection.client('guardduty', region_name=region)
                try:
                    detectors = regional_client.list_detectors()
                    if not detectors.get('DetectorIds', []):
                        return {region: False}, False

                    region_status = {}
                    for detector_id in detectors['DetectorIds']:
                        resource_key = f"{region}-{detector_id}"
                        try:
                            detector = regional_client.get_detector(DetectorId=detector_id)
                            if detector.get('Status') is None or not detector.get('Status'):
                                region_status[resource_key] = False
                                return region_status, False
                            else:
                                region_status[resource_key] = True
                        except ClientError:
                            region_status[resource_key] = False
                            return region_status, False

                    return region_status, True

                except ClientError:
                    return {region: False}, False

            max_threads = 31  
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                results = list(executor.map(check_region, available_regions))

            for region_status, passed in results:
                report.resource_ids_status.update(region_status)
                if not passed:
                    report.passed = False

        except Exception:
            report.passed = False

        return report
