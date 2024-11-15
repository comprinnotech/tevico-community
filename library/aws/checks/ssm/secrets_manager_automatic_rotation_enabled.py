"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-11
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class secrets_manager_automatic_rotation_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        secretsmanager_client = connection.client('secretsmanager')
        
        secrets = secretsmanager_client.list_secrets()['SecretList']
        
        for secret in secrets:
            secret_id = secret['ARN']
            rotation_enabled = secret.get('RotationEnabled', False)
            
            report.resource_ids_status[secret_id] = rotation_enabled

        return report
