"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class vpc_service_endpoint_enabled(Check):

    def _get_vpcs(self, ec2_client):
        try:
            response = ec2_client.describe_vpcs()
            return response.get('Vpcs', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _get_vpc_endpoints(self, ec2_client, vpc_id):
        try:
            response = ec2_client.describe_vpc_endpoints(
                Filters=[{
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }]
            )
            return response.get('VpcEndpoints', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _has_available_endpoint(self, endpoints):
      
        for endpoint in endpoints:
            if endpoint.get('State') == 'available':
                return True
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
      
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            ec2_client = connection.client('ec2')
            vpcs = self._get_vpcs(ec2_client)
            
            if not vpcs:
                report.passed = False
                report.resource_ids_status['NO_VPCS_FOUND'] = False
                return report

            # Initialize all VPCs as not compliant
            for vpc in vpcs:
                vpc_id = vpc.get('VpcId')
                if vpc_id:
                    report.resource_ids_status[vpc_id] = False

            # Check each VPC for endpoints
            for vpc in vpcs:
                vpc_id = vpc.get('VpcId')
                if not vpc_id:
                    continue

                endpoints = self._get_vpc_endpoints(ec2_client, vpc_id)
                has_available_endpoint = self._has_available_endpoint(endpoints)
                
                # If any VPC doesn't have an available endpoint, the entire check fails
                if not has_available_endpoint:
                    report.passed = False
                    report.resource_ids_status[vpc_id] = False
                else:
                    report.resource_ids_status[vpc_id] = True

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        return report
