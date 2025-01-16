"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-17
"""

import boto3
import tempfile
import os
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import transient_settings
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class lambda_function_no_secrets_in_code(Check):
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

                # Get the function code configuration
                try:
                    response = client.get_function(FunctionName=function_name)
                    code_url = response['Code']['Location']

                    # Download the function code
                    code = self.download_code_from_url(code_url)

                    # Scan code for potential secrets
                    secrets_found = self.detect_secrets_scan(data=code)
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

    def detect_secrets_scan(self, data: str = None, file=None, excluded_secrets: list[str] = None) -> list[dict[str, str]]:
        """
        Scans the data or file for secrets using the detect-secrets library.
        """
        try:
            if not file:
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
            if excluded_secrets and len(excluded_secrets) > 0:
                settings["filters_used"].append(
                    {
                        "path": "detect_secrets.filters.regex.should_exclude_line",
                        "pattern": excluded_secrets,
                    }
                )
            with transient_settings(settings):
                if file:
                    secrets.scan_file(file)
                else:
                    secrets.scan_file(temp_data_file.name)

            if not file:
                os.remove(temp_data_file.name)

            detect_secrets_output = secrets.json()

            if detect_secrets_output:
                if file:
                    return detect_secrets_output[file]
                else:
                    return detect_secrets_output[temp_data_file.name]
            else:
                return None
        except Exception as e:
            return None

    def download_code_from_url(self, url: str) -> str:
        """
        Downloads the Lambda function code from the provided URL.
        """
        import requests

        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            raise Exception(f"Failed to download Lambda code. Status code: {response.status_code}")
