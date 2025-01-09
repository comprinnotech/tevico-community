"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-08
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class networkfirewall_multi_az_enabled(Check):

    def _get_firewalls(self, client):
        """Retrieve the list of all Network Firewalls."""
        try:
            response = client.list_firewalls()
            return response.get('Firewalls', [])
        except (ClientError, BotoCoreError):
            return []

    def _get_firewall_details(self, client, firewall_name):
        """Retrieve subnet mappings for a specific Network Firewall."""
        try:
            response = client.describe_firewall(FirewallName=firewall_name)
            return response.get('Firewall', {}).get('SubnetMappings', [])
        except (ClientError, BotoCoreError):
            return []

    def _get_subnet_azs(self, ec2_client, subnet_ids):
        """Retrieve unique availability zones for the given subnet IDs."""
        try:
            response = ec2_client.describe_subnets(SubnetIds=subnet_ids)
            return {subnet['AvailabilityZone'] for subnet in response.get('Subnets', [])}
        except (ClientError, BotoCoreError):
            return set()

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report with a default pass status
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Create clients for Network Firewall and EC2
            client = connection.client('network-firewall')
            ec2_client = connection.client('ec2')

            # Get all firewalls
            firewalls = self._get_firewalls(client)

            if not firewalls:
                # No firewalls found
                report.passed = False
                report.resource_ids_status['No Network Firewalls found'] = False
                return report

            for firewall in firewalls:
                firewall_name = firewall.get('FirewallName', 'Unknown')
                subnet_mappings = self._get_firewall_details(client, firewall_name)

                # Extract subnet IDs and determine unique AZs
                subnet_ids = [mapping['SubnetId'] for mapping in subnet_mappings]
                unique_azs = self._get_subnet_azs(ec2_client, subnet_ids)

                # Check if the firewall spans multiple AZs
                if len(unique_azs) < 2:
                    report.passed = False
                    report.resource_ids_status[firewall_name] = False
                else:
                    report.resource_ids_status[firewall_name] = True

        except (ClientError, BotoCoreError):
            # Handle AWS API errors
            report.passed = False
            report.resource_ids_status['Error checking Network Firewall configuration'] = False
        except Exception:
            # Handle unexpected exceptions
            report.passed = False
            report.resource_ids_status['Error checking Network Firewall configuration'] = False

        return report
