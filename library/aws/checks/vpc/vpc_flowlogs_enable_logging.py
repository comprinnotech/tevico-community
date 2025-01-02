"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckReport

class vpc_flowlogs_enable_logging(Check):
    def _get_vpcs(self, ec2_client):
        try:
            response = ec2_client.describe_vpcs()
            return response.get('Vpcs', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _get_flow_logs(self, ec2_client, vpc_id):
        try:
            response = ec2_client.describe_flow_logs(
                Filters=[{
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }]
            )
            return response.get('FlowLogs', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _check_flow_log_status(self, flow_logs):
        for flow_log in flow_logs:
            if flow_log.get('FlowLogStatus') == 'ACTIVE':
                return True
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            ec2_client = connection.client('ec2')
            vpcs = self._get_vpcs(ec2_client)
            
            if not vpcs:
                report.resource_ids_status['NO_VPCS_FOUND'] = True
                return report

            for vpc in vpcs:
                vpc_id = vpc.get('VpcId')
                if not vpc_id:
                    continue

                flow_logs = self._get_flow_logs(ec2_client, vpc_id)
                has_active_flow_logs = self._check_flow_log_status(flow_logs)
                report.resource_ids_status[f'vpc-{vpc_id}'] = has_active_flow_logs
                
                if not has_active_flow_logs:
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        return report
