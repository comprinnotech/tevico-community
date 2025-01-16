"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import boto3
import base64
import re

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_launch_template_no_secrets(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED  # Assume passed unless secrets are found
        report.resource_ids_status = {}

        try:
            # Fetch all launch templates
            templates_response = ec2_client.describe_launch_templates()
            launch_templates = templates_response.get('LaunchTemplates', [])
        except Exception as e:
            report.status = ResourceStatus.FAILED
            #report.message = f"Error fetching launch templates: {str(e)}"
            return report

        if not launch_templates:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status['No Launch Templates'] = False  # No launch templates found
            return report

        for template in launch_templates:
            template_id = template['LaunchTemplateId']
            template_name = template['LaunchTemplateName']

            # Fetch launch template versions to get user data
            try:
                version_response = ec2_client.describe_launch_template_versions(
                    LaunchTemplateId=template_id
                )
                versions = version_response['LaunchTemplateVersions']
            except Exception as e:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[template_name] = False
                #report.message = f"Error fetching template versions for {template_name}: {str(e)}"
                continue

            for version in versions:
                version_number = version['VersionNumber']
                user_data_encoded = version.get('LaunchTemplateData', {}).get('UserData', '')

                if user_data_encoded:
                    try:
                        # Decode user data from base64
                        decoded_user_data = base64.b64decode(user_data_encoded).decode('utf-8', errors='ignore')
                    except Exception as e:
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[f"{template_name}-v{version_number}"] = False
                        #report.message = f"Error decoding user data for {template_name} version {version_number}: {str(e)}"
                        continue

                    # Check for sensitive information
                    if self.contains_sensitive_data(decoded_user_data):
                        report.status = ResourceStatus.FAILED
                        report.resource_ids_status[f"{template_name}-v{version_number}"] = False
                        # report.resource_ids_status[f"{template_name}-v{version_number}"] = (
                        #    f"Launch Template {template_name} version {version_number} contains sensitive data in user data."
                        #)
                else:
                    report.resource_ids_status[f"{template_name}-v{version_number}"] = True  # No secrets, user data is empty

        return report

    def contains_sensitive_data(self, user_data: str) -> bool:
        """Check if the user data contains sensitive information."""
        sensitive_keywords = [
            'password', 'secret', 'token', 'api_key', 'aws_secret_access_key',
            'aws_access_key_id', 'client_secret', 'username', 'credential',
            'db_password', 'mysql_pass', 'postgres_pass', 'mongodb_pass'
        ]

        # Regular expressions for matching patterns
        regex_patterns = [
            r'(?i)(?:password\s*=\s*|(?<=\s))([A-Za-z0-9/+=]{20,})',  # Detecting passwords
            r'(?i)(?:api[-_.]?[Kk]ey|token|secret)[\s=:]*([A-Za-z0-9/+=]{20,})',  # API keys and tokens
            r'(?i)[A-Za-z0-9/+=]{32,}',  # Catching long random strings
            r'(?i)(aws_access_key_id|aws_secret_access_key|client_secret)[\s=:]*([A-Za-z0-9/+=]+)',  # AWS keys
        ]

        # Check for sensitive keywords
        if any(keyword in user_data.lower() for keyword in sensitive_keywords):
            return True

        # Check against regex patterns
        for pattern in regex_patterns:
            if re.search(pattern, user_data):
                return True

        # Optional: Check for high entropy strings (indicative of secrets)
        if self.is_high_entropy(user_data):
            return True

        return False

    def is_high_entropy(self, string: str, threshold: float = 3.0) -> bool:
        """ Check if the string has high entropy, often a sign of secrets. """
        if not string:
            return False
        prob = {char: string.count(char) / len(string) for char in set(string)}
        entropy = -sum(p * (p ** 0.5) for p in prob.values())  # Simplified entropy calculation
        return entropy > threshold