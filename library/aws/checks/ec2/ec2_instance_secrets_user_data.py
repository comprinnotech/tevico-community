"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-15
"""

import boto3
import base64
import re
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import (
    CheckReport, CheckStatus, GeneralResource, ResourceStatus
)
from tevico.engine.entities.check.check import Check


class ec2_instance_secrets_user_data(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        # Enhanced checks for sensitive data in user data
        sensitive_keywords = [
            'password', 'secret', 'token', 'api_key', 'aws_secret_access_key',
            'aws_access_key_id', 'client_secret', 'username', 'credential', 
            'db_password', 'mysql_pass', 'postgres_pass', 'mongodb_pass',
            'key', 'pin', 'connection', 'auth', 'authentication', 'api'
        ]
        

        # Regular expressions for matching patterns
        regex_patterns = [
            r'(?i)(?:password\s*=\s*|(?<=\s))([A-Za-z0-9/+=]{20,})',  # Detecting passwords
            r'(?i)(?:api[-_.]?[Kk]ey|token|secret)[\s=:]*([A-Za-z0-9/+=]{20,})',  # API keys and tokens
            r'(?i)[A-Za-z0-9/+=]{32,}',  # Catching long random strings
            r'(?i)(aws_access_key_id|aws_secret_access_key|client_secret)[\s=:]*([A-Za-z0-9/+=]+)',  # AWS keys
        ]

        try:
            paginator = ec2_client.get_paginator('describe_instances')
            has_running_instances = False

            for page in paginator.paginate():
                reservations = page.get('Reservations', [])
                if reservations:
                    has_running_instances = True

                for reservation in reservations:
                    for instance in reservation.get('Instances', []):
                        state = instance.get('State', {}).get('Name', '').lower()
                        if state in ["pending", "terminated", ]:
                            continue  # Skip these states

                        instance_id = instance['InstanceId']
                        user_data = ec2_client.describe_instance_attribute(
                            InstanceId=instance_id, Attribute='userData'
                        ).get('UserData', {}).get('Value')
                        
                        if user_data:
                            decoded_user_data = base64.b64decode(user_data).decode('utf-8', errors='ignore')
                            
                            if any(keyword in decoded_user_data.lower() for keyword in sensitive_keywords) or \
                               any(re.search(pattern, decoded_user_data) for pattern in regex_patterns):
                                status = CheckStatus.FAILED
                                summary = f"EC2 instance {instance_id} contains sensitive information in user data."
                            else:
                                status = CheckStatus.PASSED
                                summary = f"EC2 instance {instance_id} does not contain sensitive information in user data."
                        else:
                            status = CheckStatus.PASSED
                            summary = f"EC2 instance {instance_id} has no user data."

                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=instance_id),
                                status=status,
                                summary=summary
                            )
                        )

            if not has_running_instances:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No running EC2 instances found."
                    )
                )
                return report

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EC2 user data.",
                    exception=str(e)
                )
            )

        return report
