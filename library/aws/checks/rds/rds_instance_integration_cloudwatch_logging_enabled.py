"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class rds_instance_integration_cloudwatch_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('rds')
            instances = client.describe_db_instances()['DBInstances']
            report.status = ResourceStatus.PASSED  

            for instance in instances:
                instance_name = instance['DBInstanceIdentifier']
                logging_enabled = instance.get('EnabledCloudwatchLogsExports', [])
                if logging_enabled:
                    report.resource_ids_status[instance_name] = True
                else:
                    report.resource_ids_status[instance_name] = False
                    report.status = ResourceStatus.FAILED  
                     
        except Exception as e:
            report.status = ResourceStatus.FAILED
            return report

        return report
