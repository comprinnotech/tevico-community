"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_storage_encrypted(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('rds')
        instances = client.describe_db_instances()['DBInstances']
        
        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            storage_encrypted = instance['StorageEncrypted']
            
            if storage_encrypted:
                report.passed = True
                report.resource_ids_status[instance_name] = True
            else:
                report.passed = False
                report.resource_ids_status[instance_name] = False
        
        return report
