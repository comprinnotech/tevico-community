import boto3

from tevico.framework.entities.report.scan_model import ScanReport
from tevico.framework.entities.scan.scan import Scan


class rds_instance_deletion_protection(Scan):

    def execute(self, connection: boto3.Session) -> ScanReport:
        report = ScanReport()
        client = connection.client('rds')
        instances = client.describe_db_instances()['DBInstances']
        
        for instance in instances:
            instance_name = instance['DBInstanceIdentifier']
            
            if instance['DeletionProtection']:
                report.passed = True
                report.resource_ids_status[instance_name] = True
            else:
                report.passed = False
                report.resource_ids_status[instance_name] = False
                
        return report

    