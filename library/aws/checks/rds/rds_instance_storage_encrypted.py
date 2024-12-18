"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_storage_encrypted(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('rds')
            instances = client.describe_db_instances()['DBInstances']
            report.passed = True  
            
            for instance in instances:
                instance_name = instance['DBInstanceIdentifier']
                storage_encrypted = instance['StorageEncrypted']
                
                if storage_encrypted:
                    report.resource_ids_status[instance_name] = True
                else:
                    report.passed = False
                    report.resource_ids_status[instance_name] = False
                        
        except Exception as e:
            report.passed = False
            return report

        return report

