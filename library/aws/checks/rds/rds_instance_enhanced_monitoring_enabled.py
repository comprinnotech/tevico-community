import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class rds_instance_enhanced_monitoring_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('rds')
        instances = client.describe_db_instances()['DBInstances']
        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            enhanced_monitoring = instance.get('EnhancedMonitoringResourceArn')
            # print(f'instance = {instance}')
            
            if enhanced_monitoring:
                report.passed = True
                report.resource_ids_status[instance_name] = True
            else:
                report.passed = False
                report.resource_ids_status[instance_name] = False

        return report

    