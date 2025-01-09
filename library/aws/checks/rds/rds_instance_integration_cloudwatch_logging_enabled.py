"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_integration_cloudwatch_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False  # Initialize as False by default
        
        try:
            client = connection.client('rds')
            instances = client.describe_db_instances()['DBInstances']

            if not instances:
                report.resource_ids_status['No RDS instances found'] = False
                return report  

            # Set to True only if we find instances, will be set to False if any check fails
            report.passed = True

            for instance in instances:
                try:
                    instance_name = instance['DBInstanceIdentifier']
                    enabled_logs = instance.get('EnabledCloudwatchLogsExports', [])
                    
                    # Check if any logs are enabled
                    has_enabled_logs = bool(enabled_logs)
                    
                    report.resource_ids_status[instance_name] = has_enabled_logs
                    
                    # If any single instance check fails, the entire check fails
                    if not has_enabled_logs:
                        report.passed = False

                except KeyError:
                    report.resource_ids_status[f'Unknown-{instance.get("DBInstanceIdentifier", "Instance")}'] = False
                    report.passed = False
                     
        except ClientError as ce:
            report.resource_ids_status['Error'] = False
            return report

        except Exception as e:
            report.resource_ids_status['Error'] = False
            return report

        return report
