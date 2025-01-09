"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class secrets_manager_automatic_rotation_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True  # Initial State: Start with True

        try:
            secretsmanager_client = connection.client('secretsmanager')
            response = secretsmanager_client.list_secrets()

            # No Resources Case: Return with passed=True if no secrets exist
            if 'SecretList' not in response or not response['SecretList']:
                return report

            # Compliance Logic: Check each secret
            for secret in response['SecretList']:
                secret_id = secret['ARN']
                rotation_enabled = secret.get('RotationEnabled', False)
                
                # Track status for each secret
                report.resource_ids_status[secret_id] = rotation_enabled

                # Set passed to False if any secret doesn't have rotation enabled
                if not rotation_enabled:
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error'] = False

        return report
