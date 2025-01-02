"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class vpc_endpoint_services_allowed_principals_trust_boundaries(Check):
    def _get_trusted_account_id(self, sts_client):
        """Get the current AWS account ID"""
        try:
            response = sts_client.get_caller_identity()
            return response.get('Account')
        except (ClientError, BotoCoreError):
            return None

    def _get_endpoint_services(self, ec2_client):
        """Get all VPC endpoint services"""
        try:
            response = ec2_client.describe_vpc_endpoint_services()
            return response.get('ServiceDetails', [])
        except (ClientError, BotoCoreError):
            return []

    def _validate_principal(self, principal, trusted_account_id):
        """Validate if principal belongs to trusted account"""
        try:
            # Handle both account ID and ARN formats
            if principal.isdigit():
                return principal == trusted_account_id
            return principal.split(':')[4] == trusted_account_id
        except (IndexError, AttributeError):
            return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Initialize AWS clients
            ec2_client = connection.client('ec2')
            sts_client = connection.client('sts')

            # Get trusted account ID
            trusted_account_id = self._get_trusted_account_id(sts_client)
            if not trusted_account_id:
                report.resource_ids_status['Failed to get account ID'] = False
                report.passed = False
                return report

            # Get VPC endpoint services
            endpoint_services = self._get_endpoint_services(ec2_client)
            if not endpoint_services:
                report.resource_ids_status['No VPC endpoint services found'] = True
                return report

            # Check each service's principals
            for service in endpoint_services:
                service_name = service.get('ServiceName', 'Unknown')
                allowed_principals = service.get('AllowedPrincipals', [])

                # Skip if no principals are defined
                if not allowed_principals:
                    report.resource_ids_status[service_name] = True
                    continue

                # Check each principal
                for principal in allowed_principals:
                    if not self._validate_principal(principal, trusted_account_id):
                        report.resource_ids_status[service_name] = False
                        report.passed = False
                        break
                else:
                    report.resource_ids_status[service_name] = True

        except (ClientError, BotoCoreError) as e:
            report.resource_ids_status['Error checking VPC endpoint services'] = False
            report.passed = False

        return report
