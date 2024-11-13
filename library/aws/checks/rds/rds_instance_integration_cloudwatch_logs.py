import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class rds_instance_integration_cloudwatch_logs(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('rds')
        instances = client.describe_db_instances()['DBInstances']
        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            
            try:
                cloudwatch_logs = client.describe_db_log_files(DBInstanceIdentifier=instance_name)
            except Exception as e:
                # print(f'Warning (Ignore): {e}')
                continue
            
            if cloudwatch_logs:
                report.passed = True
                report.resource_ids_status[instance['DBInstanceIdentifier']] = True
            else:
                report.passed = False
                report.resource_ids_status[instance['DBInstanceIdentifier']] = False
        return report

    