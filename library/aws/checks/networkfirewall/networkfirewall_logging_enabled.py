"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class networkfirewall_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('network-firewall')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        firewalls = client.list_firewalls()

        for firewall in firewalls.get('Firewalls', []):
            firewall_name = firewall['FirewallName']
            firewall_arn = firewall['FirewallArn']
            try:
                logging_config = client.describe_logging_configuration(FirewallArn=firewall_arn)
                if 'LoggingConfiguration' in logging_config and logging_config['LoggingConfiguration'].get('LogDestinationConfigs'):
                    report.resource_ids_status[firewall_name] = True
                else:
                    report.resource_ids_status[firewall_name] = False
                    report.status = ResourceStatus.FAILED
            except client.exceptions.ResourceNotFoundException:
                report.resource_ids_status[firewall_name] = False
                report.status = ResourceStatus.FAILED

        return report
