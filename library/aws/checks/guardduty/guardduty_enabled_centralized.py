"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-11
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class guardduty_enabled_centralized(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('guardduty')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Check all available GuardDuty regions
        available_regions = connection.get_available_regions('guardduty')
        
        for region in available_regions:
            try:
                regional_client = connection.client('guardduty', region_name=region)
                detectors = regional_client.list_detectors()
                
                if detectors['DetectorIds']:
                    detector_id = detectors['DetectorIds'][0]
                    detector_info = regional_client.get_detector(DetectorId=detector_id)
                    
                    # Check if GuardDuty is active
                    if detector_info['Status'] != 'ENABLED':
                        report.resource_ids_status[f"{region}-{detector_id}"] = False
                        report.status = ResourceStatus.FAILED
                        continue
                    
                    # Check if the account is a member of a centralized (administrator) GuardDuty account
                    try:
                        admin_account = regional_client.get_master_account(DetectorId=detector_id)
                        if 'Master' in admin_account and admin_account['Master']['RelationshipStatus'] == 'Enabled':
                            report.resource_ids_status[f"{region}-{detector_id}"] = True
                        else:
                            report.resource_ids_status[f"{region}-{detector_id}"] = False
                            report.status = ResourceStatus.FAILED
                    except regional_client.exceptions.BadRequestException:
                        report.resource_ids_status[f"{region}-{detector_id}"] = False
                        report.status = ResourceStatus.FAILED
                else:
                    # No detectors found in this region, mark check as failed for centralization purposes
                    report.status = ResourceStatus.FAILED
            
            except ClientError as error:
                # Handle access errors
                if error.response['Error']['Code'] == 'UnrecognizedClientException':
                    report.status = ResourceStatus.FAILED
                    continue
                else:
                    raise

        return report
