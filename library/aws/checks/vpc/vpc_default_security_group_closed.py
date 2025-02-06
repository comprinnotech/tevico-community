"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus
from tevico.engine.entities.check.check import Check



class vpc_default_security_group_closed(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        ec2_client = connection.client('ec2')

        try:
            vpcs = ec2_client.describe_vpcs()
            all_closed = True

            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                response = ec2_client.describe_security_groups(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'group-name', 'Values': ['default']}
                    ]
                )

                for sg in response['SecurityGroups']:
                    if sg['IpPermissions'] or sg['IpPermissionsEgress']:
                        all_closed = False
                        break

                if not all_closed:
                    break

            if not all_closed:
                report.status = CheckStatus.FAILED
        except Exception as e:
            report.status = CheckStatus.FAILED

        return report
