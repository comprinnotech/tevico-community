"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-10
"""

from time import process_time_ns
import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_managed_instance_patch_compliance_status(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        client = connection.client('ssm')
        
        managed_instances = client.describe_instance_information()['InstanceInformationList']
        report.status = ResourceStatus.PASSED  
        
        for instance in managed_instances:
            instance_id = instance['InstanceId']
            
            try:
                patch_states = client.describe_instance_patch_states(InstanceIds=[instance_id])['InstancePatchStates']
                for patch_state in patch_states:
                    if patch_state['ComplianceStatus'] != 'COMPLIANT':
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[instance_id] = False
                    else:
                        report.resource_ids_status[instance_id] = True
            except Exception as e:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[instance_id] = False
                
        return report
        
