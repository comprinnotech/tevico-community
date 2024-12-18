"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckReport


class vpc_flowlogs_analyze_logs(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        ec2_client = connection.client('ec2')
        sts_client = connection.client('sts')

        try:
            account_id = sts_client.get_caller_identity()['Account']
            region = connection.region_name

            vpcs = ec2_client.describe_vpcs()
            logs_analyzed = True

            vpc_ids = [vpc['VpcId'] for vpc in vpcs['Vpcs']]
            flow_logs_response = ec2_client.describe_flow_logs(Filters=[{
                'Name': 'resource-id',
                'Values': vpc_ids
            }])

            for flow_log in flow_logs_response['FlowLogs']:
                resource_id = flow_log.get('ResourceId')
                status = flow_log.get('FlowLogStatus')

                if status != 'ACTIVE':
                    logs_analyzed = False
                    break

            for vpc_id in vpc_ids:
                if vpc_id not in [flow_log.get('ResourceId') for flow_log in flow_logs_response['FlowLogs']]:
                    logs_analyzed = False
                    break

            report.passed = logs_analyzed
            report.resource_ids_status['VPC_FLOW_LOGS'] = logs_analyzed

            if not any(status for status in report.resource_ids_status.values()):
                report.passed = False

        except Exception:
            report.passed = False
            report.resource_ids_status['VPC_FLOW_LOGS'] = False

        return report
