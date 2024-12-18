import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class rds_instance_multi_az(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            client = connection.client('rds')
            response = client.describe_db_instances()
            report.passed = True 
            
            for instance in response['DBInstances']:
                instance_id = instance['DBInstanceIdentifier']
                multi_az = instance['MultiAZ']
                
                if not multi_az:
                    report.passed = False
                    report.resource_ids_status[instance_id] = False
                else:
                    report.resource_ids_status[instance_id] = True
                    
        except Exception as e:
            report.passed = False
            return report

        return report
