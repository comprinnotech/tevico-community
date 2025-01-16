import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class rds_instance_enhanced_monitoring_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('rds')
            report.status = ResourceStatus.PASSED
            instances = client.describe_db_instances()['DBInstances']
            
            for instance in instances:
                instance_name = instance['DBInstanceIdentifier']
                enhanced_monitoring = instance.get('EnhancedMonitoringResourceArn')
                
                if enhanced_monitoring:
                    report.resource_ids_status[instance_name] = True
                else:
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[instance_name] = False
                    
        except Exception as e:
            report.status = ResourceStatus.FAILED
            return report

        return report
