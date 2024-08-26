import boto3

from tevico.framework.entities.report.scan_model import ScanReport
from tevico.framework.entities.scan.scan import Scan


class cloudtrail_cloudwatch_logging_enabled(Scan):

    def execute(self, connection: boto3.Session) -> ScanReport:
        client = connection.client('cloudtrail')
        res = client.describe_trails()
        
        trails = res['trailList']
        
        report = ScanReport(name=__name__)
        
        for trail in trails:
            trail_name = trail['Name']

            res = client.get_event_selectors(TrailName=trail_name)
            event_selectors = res['EventSelectors']
            
            report.passed = False
            report.resource_ids_status[trail_name] = False

            for event_selector in event_selectors:
                if event_selector['ReadWriteType'] == 'All' and event_selector['IncludeManagementEvents'] == True:
                    report.passed = True
                    report.resource_ids_status[trail_name] = True

        return report
