"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-17
"""

import boto3
import tempfile
import os
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings

class lambda_function_no_secrets_in_variables(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('lambda')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED

        # List all Lambda functions
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            functions = page.get('Functions', [])
            for function in functions:
                function_name = function['FunctionName']

                # Get function configuration
                try:
                    response = client.get_function_configuration(FunctionName=function_name)
                    environment_variables = response.get('Environment', {}).get('Variables', {})

                    # Convert environment variables to a temporary data string for scanning
                    env_variables_data = "\n".join([f"{key}={value}" for key, value in environment_variables.items()])

                    # Scan for secrets
                    secrets_found = self.detect_secrets_scan(data=env_variables_data)
                    if secrets_found:
                        report.resource_ids_status[function_name] = False
                        report.status = ResourceStatus.FAILED
                    else:
                        report.resource_ids_status[function_name] = True

                except client.exceptions.ResourceNotFoundException:
                    report.resource_ids_status[function_name] = False
                    report.status = ResourceStatus.FAILED
                except Exception as e:
                    report.resource_ids_status[function_name] = False
                    report.status = ResourceStatus.FAILED

        return report

    def detect_secrets_scan(self, data: str = None) -> bool:
        """
        Scans the given data for secrets using the detect-secrets library.
        """
        try:
            temp_data_file = tempfile.NamedTemporaryFile(delete=False)
            temp_data_file.write(bytes(data, encoding="raw_unicode_escape"))
            temp_data_file.close()

            secrets = SecretsCollection()

            settings = {
                "plugins_used": [
                    {"name": "ArtifactoryDetector"},
                    {"name": "AWSKeyDetector"},
                    {"name": "BasicAuthDetector"},
                    {"name": "CloudantDetector"},
                    {"name": "DiscordBotTokenDetector"},
                    {"name": "GitHubTokenDetector"},
                    {"name": "GitLabTokenDetector"},
                    {"name": "Base64HighEntropyString", "limit": 6.0},
                    {"name": "HexHighEntropyString", "limit": 3.0},
                    {"name": "IbmCloudIamDetector"},
                    {"name": "IbmCosHmacDetector"},
                    {"name": "JwtTokenDetector"},
                    {"name": "KeywordDetector"},
                    {"name": "MailchimpDetector"},
                    {"name": "NpmDetector"},
                    {"name": "OpenAIDetector"},
                    {"name": "PrivateKeyDetector"},
                    {"name": "PypiTokenDetector"},
                    {"name": "SendGridDetector"},
                    {"name": "SlackDetector"},
                    {"name": "SoftlayerDetector"},
                    {"name": "SquareOAuthDetector"},
                    {"name": "StripeDetector"},
                    {"name": "TwilioKeyDetector"},
                ],
                "filters_used": [
                    {"path": "detect_secrets.filters.common.is_invalid_file"},
                    {"path": "detect_secrets.filters.common.is_known_false_positive"},
                    {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
                    {"path": "detect_secrets.filters.heuristic.is_potential_secret"},
                ],
            }

            with transient_settings(settings):
                secrets.scan_file(temp_data_file.name)

            os.remove(temp_data_file.name)
            detect_secrets_output = secrets.json()
            return bool(detect_secrets_output)
        except Exception as e:
            return False
