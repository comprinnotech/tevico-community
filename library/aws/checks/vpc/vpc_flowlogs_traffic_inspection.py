"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class vpc_flowlogs_traffic_inspection(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('ec2')
        vpcs = client.describe_vpcs()
        
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            flow_logs_enabled = False
            flow_logs = client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
            
            for flow_log in flow_logs['FlowLogs']:
                if flow_log['FlowLogStatus'] == 'ACTIVE':
                    flow_logs_enabled = True
                    break
            
            if flow_logs_enabled:
                report.resource_ids_status[vpc_id] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[vpc_id] = False
        
        return report
