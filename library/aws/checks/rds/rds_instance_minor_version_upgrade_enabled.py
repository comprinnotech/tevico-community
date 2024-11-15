"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class rds_instance_minor_version_upgrade_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        rds_client = connection.client('rds')
        
       
        db_instances = rds_client.describe_db_instances()['DBInstances']
        
       
        for db_instance in db_instances:
            db_instance_id = db_instance['DBInstanceIdentifier']
            auto_minor_version_upgrade = db_instance['AutoMinorVersionUpgrade']
            report.resource_ids_status[db_instance_id] = auto_minor_version_upgrade
        
        return report
