"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_minor_version_upgrade_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False
        
        try:
            rds_client = connection.client('rds')
            db_instances = rds_client.describe_db_instances()['DBInstances']
            
            if not db_instances:
                report.resource_ids_status['No RDS instances found'] = False
                return report
            
            # Start with assumption all instances will pass
            all_instances_enabled = True
            
            for db_instance in db_instances:
                try:
                    db_instance_id = db_instance['DBInstanceIdentifier']
                    auto_minor_version_upgrade = db_instance.get('AutoMinorVersionUpgrade', False)
                    
                    is_enabled = bool(auto_minor_version_upgrade)
                    report.resource_ids_status[db_instance_id] = is_enabled
                    
                    # If any instance doesn't have auto minor version upgrade enabled, mark for failure
                    if not is_enabled:
                        all_instances_enabled = False
                        
                except KeyError:
                    report.resource_ids_status[db_instance.get('DBInstanceIdentifier', 'Unknown')] = False
                    all_instances_enabled = False
            
            # Set final pass/fail status after checking all instances
            report.passed = all_instances_enabled
                    
        except ClientError as ce:
            report.resource_ids_status['Error'] = False
            return report
            
        except Exception as e:
            report.resource_ids_status['Error'] = False
            return report

        return report

