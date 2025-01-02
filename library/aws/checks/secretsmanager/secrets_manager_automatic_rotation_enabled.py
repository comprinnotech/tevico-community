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
        report.passed = True

        try:
            secretsmanager_client = connection.client('secretsmanager')
            response = secretsmanager_client.list_secrets()

            # Check if there are any secrets
            if 'SecretList' not in response or not response['SecretList']:
                report.passed = False
                report.resource_ids_status['No secrets found'] = False
                return report

            # Check rotation status for each secret
            for secret in response['SecretList']:
                secret_id = secret['ARN']
                rotation_enabled = secret.get('RotationEnabled', False)
                
                report.resource_ids_status[secret_id] = rotation_enabled

                # If any secret doesn't have rotation enabled, mark check as failed
                if not rotation_enabled:
                    report.passed = False

        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            report.resource_ids_status['Error'] = False

        return report
