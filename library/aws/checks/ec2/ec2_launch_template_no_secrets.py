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


class ec2_launch_template_no_secrets(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)

        try:
            paginator = ec2_client.get_paginator('describe_launch_templates')
            all_templates = []

            for page in paginator.paginate():
                all_templates.extend(page.get('LaunchTemplates', []))

            if not all_templates:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No EC2 launch templates found."
                    )
                )
                return report

            # Keywords and compiled regex for sensitive data detection
            sensitive_keywords = {
                'password', 'secret', 'token', 'api_key', 'aws_secret_access_key',
                'aws_access_key_id', 'client_secret', 'username', 'credential',
                'db_password', 'mysql_pass', 'postgres_pass', 'mongodb_pass',
                'key', 'pin', 'connection', 'auth', 'authentication', 'api'
            }

            regex_patterns = [
                re.compile(r'(?i)(?:password\s*=\s*|(?<=\s))([A-Za-z0-9/+=]{20,})'),  # Password detection
                re.compile(r'(?i)(?:api[-_.]?[Kk]ey|token|secret)[\s=:]*([A-Za-z0-9/+=]{20,})'),  # API keys/tokens
                re.compile(r'(?i)[A-Za-z0-9/+=]{32,}'),  # Long random strings (potential secrets)
                re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key|client_secret)[\s=:]*([A-Za-z0-9/+=]+)')  # AWS keys
            ]

            for template in all_templates:
                template_id = template['LaunchTemplateId']

                try:
                    versions = ec2_client.describe_launch_template_versions(
                        LaunchTemplateId=template_id
                    ).get('LaunchTemplateVersions', [])
                except (BotoCoreError, ClientError) as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=template_id),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving launch template versions for {template_id}.",
                            exception=str(e)
                        )
                    )
                    continue

                for version in versions:
                    user_data = version.get('LaunchTemplateData', {}).get('UserData')
                    if not user_data:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=template_id),
                                status=CheckStatus.PASSED,
                                summary=f"Launch template {template_id} has no user data."
                            )
                        )
                        continue

                    try:
                        decoded_user_data = base64.b64decode(user_data).decode('utf-8', errors='ignore')
                    except (ValueError, UnicodeDecodeError):
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=GeneralResource(name=template_id),
                                status=CheckStatus.UNKNOWN,
                                summary=f"Could not decode user data for launch template {template_id}."
                            )
                        )
                        continue

                    # Check for sensitive information
                    contains_sensitive_data = (
                        any(keyword in decoded_user_data.lower() for keyword in sensitive_keywords) or
                        any(pattern.search(decoded_user_data) for pattern in regex_patterns)
                    )

                    status = CheckStatus.FAILED if contains_sensitive_data else CheckStatus.PASSED
                    summary = (
                        f"Launch template {template_id} contains sensitive information in user data."
                        if contains_sensitive_data
                        else f"Launch template {template_id} does not contain sensitive information in user data."
                    )

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=template_id),
                            status=status,
                            summary=summary
                        )
                    )

        except (BotoCoreError, ClientError) as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving EC2 launch template data.",
                    exception=str(e)
                )
            )

        return report
