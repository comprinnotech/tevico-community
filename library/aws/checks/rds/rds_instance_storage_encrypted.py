"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_storage_encrypted(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = False
        
        try:
            client = connection.client('rds')
            instances = client.describe_db_instances()['DBInstances']
            
            if not instances:
                report.resource_ids_status['No RDS instances found'] = False
                return report
            
            # Start with assumption all instances will pass
            all_instances_encrypted = True
            
            for instance in instances:
                try:
                    instance_name = instance['DBInstanceIdentifier']
                    storage_encrypted = instance.get('StorageEncrypted', False)
                    
                    report.resource_ids_status[instance_name] = storage_encrypted
                    
                    # If any instance is not encrypted, mark for failure
                    if not storage_encrypted:
                        all_instances_encrypted = False
                        
                except KeyError:
                    report.resource_ids_status['Unknown-Instance'] = False
                    all_instances_encrypted = False
                    
            # Set final pass/fail status after checking all instances
            report.passed = all_instances_encrypted
                    
        except ClientError as ce:
            report.resource_ids_status['Error'] = False
            return report
            
        except Exception as e:
            report.resource_ids_status['Error'] = False
            return report

        return report

