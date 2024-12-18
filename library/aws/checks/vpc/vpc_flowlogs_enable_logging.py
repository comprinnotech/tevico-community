"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class vpc_flowlogs_enable_logging(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')

        try:
            vpcs = ec2_client.describe_vpcs()
            flow_logs_enabled = True

            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                response = ec2_client.describe_flow_logs(Filters=[{
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }])

                if not response['FlowLogs']:
                    flow_logs_enabled = False
                    break  

            report.passed = flow_logs_enabled
            report.resource_ids_status['VPC_FLOW_LOGS'] = flow_logs_enabled

        except Exception as e:
            report.passed = False
            report.resource_ids_status['VPC_FLOW_LOGS'] = False

        return report
