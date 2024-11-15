"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_integration_cloudwatch_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('rds')
        instances = client.describe_db_instances()['DBInstances']
        
        all_logging_enabled = True  

        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            logging_enabled = instance.get('CloudwatchLogsExportConfiguration', {}).get('LogTypes', [])


            if logging_enabled:
                report.resource_ids_status[instance_name] = True
            else:
                report.resource_ids_status[instance_name] = False
                all_logging_enabled = False  
        
        
        report.passed = all_logging_enabled

        return report
