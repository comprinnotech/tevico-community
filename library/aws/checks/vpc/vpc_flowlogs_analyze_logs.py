"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckReport


class vpc_flowlogs_analyze_logs(Check):
    def _get_vpcs(self, ec2_client):
        """Get all VPCs in the account"""
        try:
            response = ec2_client.describe_vpcs()
            return response.get('Vpcs', [])
        except (ClientError, BotoCoreError):
            return []

    def _get_flow_logs(self, ec2_client, vpc_ids):
        """Get flow logs for specified VPCs"""
        try:
            response = ec2_client.describe_flow_logs(
                Filters=[{
                    'Name': 'resource-id',
                    'Values': vpc_ids
                }]
            )
            return response.get('FlowLogs', [])
        except (ClientError, BotoCoreError):
            return []

    def _is_valid_cloudwatch_flow_log(self, flow_log):
        """Check if flow log is properly configured for CloudWatch"""
        return (
            flow_log.get('FlowLogStatus') == 'ACTIVE' and
            flow_log.get('LogDestinationType') == 'cloud-watch-logs' and
            flow_log.get('LogGroupName') and
            flow_log.get('DeliverLogsStatus') == 'SUCCESS'
        )

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Initialize clients
            ec2_client = connection.client('ec2')
            logs_client = connection.client('logs')

            # Get all VPCs
            vpcs = self._get_vpcs(ec2_client)
            if not vpcs:
                report.resource_ids_status['No VPCs found'] = True
                return report

            # Get VPC IDs
            vpc_ids = [vpc.get('VpcId') for vpc in vpcs if vpc.get('VpcId')]
            
            # Get flow logs for these VPCs
            flow_logs = self._get_flow_logs(ec2_client, vpc_ids)

            # Check each VPC
            for vpc_id in vpc_ids:
                vpc_flow_logs = [
                    log for log in flow_logs 
                    if log.get('ResourceId') == vpc_id
                ]

                if not vpc_flow_logs:
                    # No flow logs configured for this VPC
                    report.resource_ids_status[f'vpc-{vpc_id}'] = False
                    report.passed = False
                    continue

                # Check if any flow log is properly configured for CloudWatch
                has_valid_cloudwatch_log = any(
                    self._is_valid_cloudwatch_flow_log(log)
                    for log in vpc_flow_logs
                )

                report.resource_ids_status[f'vpc-{vpc_id}'] = has_valid_cloudwatch_log
                if not has_valid_cloudwatch_log:
                    report.passed = False

        except (ClientError, BotoCoreError) as e:
            report.resource_ids_status['Error checking flow logs'] = False
            report.passed = False

        return report
