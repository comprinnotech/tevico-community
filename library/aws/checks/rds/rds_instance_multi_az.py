import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class rds_instance_multi_az(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('rds')
            response = client.describe_db_instances()
            report.status = ResourceStatus.PASSED 
            
            for instance in response['DBInstances']:
                instance_id = instance['DBInstanceIdentifier']
                multi_az = instance['MultiAZ']
                
                if not multi_az:
                    report.status = ResourceStatus.FAILED
                    report.resource_ids_status[instance_id] = False
                else:
                    report.resource_ids_status[instance_id] = True
                    
        except Exception as e:
            report.status = ResourceStatus.FAILED
            return report

        return report
