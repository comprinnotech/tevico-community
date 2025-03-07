"""
AUTHOR: Sheikh Aafaq Rashid
DATE: 10-10-2024
"""

import base64
import boto3
import re

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_instance_secrets_user_data(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        ec2_client = connection.client('ec2')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Assume passed unless we find secrets
        report.resource_ids_status = []

        # Fetch all EC2 instances
        try:
            instances_response = ec2_client.describe_instances()
            instances = [i for r in instances_response['Reservations'] for i in r['Instances']]
        except Exception as e:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error in fetching EC2 instances.",
                    exception=str(e)
                )
            )
            #report.message = f"Error fetching EC2 instances: {str(e)}"
            return report

        # Check each instance
        if not instances:
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.NOT_APPLICABLE,
                    summary=f"No EC2 instances"
                )
            )
            return report

        for instance in instances:
            instance_id = instance['InstanceId']
            instance_arn = instance['IamInstanceProfile']['Arn']

            # Retrieve user data for the instance
            try:
                user_data_response = ec2_client.describe_instance_attribute(InstanceId=instance_id, Attribute='userData')
                user_data = user_data_response.get('UserData', {}).get('Value', '')

                # Decode user data from base64
                if user_data:
                    decoded_user_data = base64.b64decode(user_data).decode('utf-8', errors='ignore')
                else:
                    decoded_user_data = ''
            except Exception as e:
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary=f"Error retrieving user data for instance {instance_id}:",
                        exception=str(e)
                    )
                )
                continue  # Skip to next instance

            # Enhanced checks for sensitive data in user data
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
            if any(keyword in decoded_user_data.lower() for keyword in sensitive_keywords):
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(Arn=instance_arn),
                        status=CheckStatus.FAILED,
                        summary=f"EC2 Instance {instance_id} has sensitive keywords in user data."
                    )
                )

            # Check against regex patterns
            for pattern in regex_patterns:
                if re.search(pattern, decoded_user_data):
                    report.status = CheckStatus.FAILED
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(Arn=instance_arn),
                            status=CheckStatus.FAILED,
                            summary=f"EC2 Instance {instance_id} has sensitive patterns in user data."
                        )
                    )
                    break  # No need to check further patterns for this instance

            # Optional: Check for high entropy strings (indicative of secrets)
            if self.is_high_entropy(decoded_user_data):
                report.status = CheckStatus.FAILED
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=AwsResource(Arn=instance_arn),
                        status=CheckStatus.FAILED,
                        summary=f"EC2 Instance {instance_id} contains high entropy strings in user data."
                    )
                )

        return report

    def is_high_entropy(self, string: str, threshold: float = 3.0) -> bool:
        """ Check if the string has high entropy. """
        if not string:
            return False
        # Calculate entropy
        prob = {char: string.count(char) / len(string) for char in set(string)}
        entropy = -sum(p * (p ** 0.5) for p in prob.values())  # Simplified entropy calculation
        return entropy > threshold