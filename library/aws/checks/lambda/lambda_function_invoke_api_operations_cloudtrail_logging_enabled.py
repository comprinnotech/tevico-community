"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class lambda_function_invoke_api_operations_cloudtrail_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudtrail')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED

        trails = client.describe_trails()['trailList']
        logging_enabled = False

        for trail in trails:
            if trail.get('IsMultiRegionTrail') and trail.get('LogFileValidationEnabled'):
                trail_status = client.get_trail_status(Name=trail['TrailARN'])
                if trail_status['IsLogging']:
                    logging_enabled = True
                    break
        
        if logging_enabled:
            report.status = ResourceStatus.PASSED
        else:
            report.status = ResourceStatus.FAILED

        return report
