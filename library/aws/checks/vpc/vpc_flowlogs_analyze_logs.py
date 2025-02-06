"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import re
import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.check.check import Check


class vpc_flowlogs_analyze_logs(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        ec2_client = connection.client('ec2')

        try:
            vpcs = ec2_client.describe_vpcs()
            logs_analyzed = True

            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                report.resource_ids_status[vpc_id] = True
                response = ec2_client.describe_flow_logs(Filters=[{
                    'Name': 'resource-id',
                    'Values': [vpc_id]
                }])

                if not response['FlowLogs']:
                    report.resource_ids_status[vpc_id] = False
                    report.status = CheckStatus.FAILED
                    break

                for flow_log in response['FlowLogs']:
                    log_group = flow_log.get('LogGroupName')
                    if not log_group:
                        report.resource_ids_status[vpc_id] = False
                        report.status = CheckStatus.FAILED
                        break

        except Exception as e:
            report.status = CheckStatus.FAILED
        
        return report
