"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3


from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class vpc_security_group_port_restriction_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        ec2_client = connection.client('ec2')
        security_groups = ec2_client.describe_security_groups()
        restricted_ports = {22, 80, 443}
        
        def has_restricted_ports(rules):
            for rule in rules:
                for port in restricted_ports:
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 0)
                    if port in {from_port, to_port}:
                        return True
            return False
        
        report.status = ResourceStatus.PASSED
        for sg in security_groups['SecurityGroups']:
            if has_restricted_ports(sg.get('IpPermissions', [])) or has_restricted_ports(sg.get('IpPermissionsEgress', [])):
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[sg['GroupId']] = False
            else:
                report.resource_ids_status[sg['GroupId']] = True
        
        return report



