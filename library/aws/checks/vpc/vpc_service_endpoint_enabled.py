"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_service_endpoint_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('ec2')
        vpcs = client.describe_vpcs()
        
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            endpoint_enabled = False
            endpoints = client.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            
            for endpoint in endpoints['VpcEndpoints']:
                if endpoint['State'] == 'available':
                    endpoint_enabled = True
                    break
            
            if endpoint_enabled:
                report.resource_ids_status[vpc_id] = True
            else:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[vpc_id] = False
        
        return report
