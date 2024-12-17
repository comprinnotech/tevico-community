"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


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

            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                response = ec2_client.describe_flow_logs(Filters=[{
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }])

                if not response['FlowLogs']:
                    logs_analyzed = False
                    break

                for flow_log in response['FlowLogs']:
                    resource_id = flow_log.get('ResourceId')
                    status = flow_log.get('FlowLogStatus')

                    # Generate ARN for Flow Logs
                    flow_log_arn = f"arn:aws:ec2:{region}:{account_id}:vpc-flow-log/{resource_id}"
                    
                    if resource_id != vpc_id or status != 'ACTIVE':
                        logs_analyzed = False
                        break

            report.passed = logs_analyzed
        except Exception:
            report.passed = False
        
        return report
