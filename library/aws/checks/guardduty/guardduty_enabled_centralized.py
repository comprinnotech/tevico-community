"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-11
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from concurrent.futures import ThreadPoolExecutor

class guardduty_enabled_centralized(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('guardduty')
        report = CheckReport(name=__name__)
        report.passed = True
        
        available_regions = connection.get_available_regions('guardduty')

        def check_region(region):
            regional_client = connection.client('guardduty', region_name=region)
            try:
                detectors = regional_client.list_detectors()
                
                if detectors['DetectorIds']:
                    detector_id = detectors['DetectorIds'][0]
                    detector_info = regional_client.get_detector(DetectorId=detector_id)
                    
                    if detector_info['Status'] != 'ENABLED':
                        report.resource_ids_status[f"{region}-{detector_id}"] = False
                        return False
                    
                    try:
                        admin_account = regional_client.get_master_account(DetectorId=detector_id)
                        if 'Master' in admin_account and admin_account['Master']['RelationshipStatus'] == 'Enabled':
                            report.resource_ids_status[f"{region}-{detector_id}"] = True
                        else:
                            report.resource_ids_status[f"{region}-{detector_id}"] = False
                            return False
                    except regional_client.exceptions.BadRequestException:
                        report.resource_ids_status[f"{region}-{detector_id}"] = False
                        return False
                else:
                    return False

            except Exception as error:
                    return False

            return True
        
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(check_region, available_regions))

        if not all(results):
            report.passed = False

        return report
