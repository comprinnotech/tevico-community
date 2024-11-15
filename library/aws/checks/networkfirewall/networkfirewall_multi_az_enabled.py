"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class networkfirewall_multi_az_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('network-firewall')
        firewalls = client.list_firewalls()['Firewalls']
        
        for firewall_info in firewalls:
            firewall_name = firewall_info['FirewallName']
            firewall_details = client.describe_firewall(FirewallName=firewall_name)
            subnet_mappings = firewall_details['Firewall']['SubnetMappings']
            
            if len(subnet_mappings) > 1:
                report.passed = True
                report.resource_ids_status[firewall_name] = True
            else:
                report.passed = False
                report.resource_ids_status[firewall_name] = False

        return report

