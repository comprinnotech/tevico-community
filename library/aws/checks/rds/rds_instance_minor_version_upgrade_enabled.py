"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

from enum import auto
import boto3
from botocore.exceptions import ClientError

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class rds_instance_minor_version_upgrade_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        
        try:
            rds_client = connection.client('rds')
            db_instances = rds_client.describe_db_instances()['DBInstances']
            report.status = CheckStatus.PASSED
            
            for db_instance in db_instances:
                
                db_instance_id = db_instance['DBInstanceIdentifier']
                auto_minor_version_upgrade = db_instance['AutoMinorVersionUpgrade']
                
                if auto_minor_version_upgrade:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=db_instance_id),
                            status=CheckStatus.PASSED,
                            summary=''
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=db_instance_id),
                            status=CheckStatus.FAILED,
                            summary=''
                        )
                    )
                    report.status = CheckStatus.FAILED
                        
                
            
        except Exception as e:
            report.status = CheckStatus.FAILED
            return report

        return report
