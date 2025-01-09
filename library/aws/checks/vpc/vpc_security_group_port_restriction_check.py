"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class vpc_security_group_port_restriction_check(Check):
    def _get_security_groups(self, ec2_client):
        try:
            response = ec2_client.describe_security_groups()
            return response.get('SecurityGroups', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _has_restricted_ports(self, rules, restricted_ports):
        for rule in rules:
            for port in restricted_ports:
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                if port in {from_port, to_port}:
                    return True
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        restricted_ports = {22, 80, 443}
        
        try:
            ec2_client = connection.client('ec2')
            security_groups = self._get_security_groups(ec2_client)
            
            if not security_groups:
                report.resource_ids_status['NO_SECURITY_GROUPS_FOUND'] = True
                return report

            for sg in security_groups:
                sg_id = sg.get('GroupId')
                if not sg_id:
                    continue

                inbound_rules = sg.get('IpPermissions', [])
                outbound_rules = sg.get('IpPermissionsEgress', [])

                has_restricted_inbound = self._has_restricted_ports(inbound_rules, restricted_ports)
                has_restricted_outbound = self._has_restricted_ports(outbound_rules, restricted_ports)

                if has_restricted_inbound or has_restricted_outbound:
                    report.passed = False
                    report.resource_ids_status[sg_id] = False
                else:
                    report.resource_ids_status[sg_id] = True

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        return report

