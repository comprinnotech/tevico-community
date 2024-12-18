import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_backup_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        try:
            client = connection.client('rds')
            instances = client.describe_db_instances()['DBInstances']
            
            for instance in instances:
                instance_name = instance['DBInstanceIdentifier']
                backup_retention_period = instance['BackupRetentionPeriod']
                
                if backup_retention_period == 0:
                    report.passed = False
                    report.resource_ids_status[instance_name] = False
                else:
                    report.resource_ids_status[instance_name] = True
            
        except Exception as e:
            report.passed = False
            return report

        return report


    