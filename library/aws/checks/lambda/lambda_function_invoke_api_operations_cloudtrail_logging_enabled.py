"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2025-03-01
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class lambda_function_invoke_api_operations_cloudtrail_logging_enabled(Check):

    def _get_trails(self, client):
        """Retrieve all CloudTrail trails."""
        try:
            response = client.describe_trails()
            return response.get('trailList', [])
        except (ClientError, BotoCoreError):
            return []

    def _get_event_selectors(self, client, trail_arn):
        """Retrieve event selectors for a specific trail."""
        try:
            response = client.get_event_selectors(TrailName=trail_arn)
            return response.get('EventSelectors', [])
        except (ClientError, BotoCoreError):
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.passed = False

        try:
            # Create CloudTrail client
            client = connection.client('cloudtrail')
            
            # Retrieve CloudTrail trails
            trails = self._get_trails(client)

            if not trails:
                # No trails found
                report.resource_ids_status['No relevant trails'] = False
                return report

            lambda_logging_found = False

            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                event_selectors = self._get_event_selectors(client, trail['TrailARN'])
                
                # Check for Lambda invoke operations logging
                has_lambda_logging = False
                for selector in event_selectors:
                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::Lambda::Function':
                            has_lambda_logging = True
                            lambda_logging_found = True
                            break
                    if has_lambda_logging:
                        break
                
                # Update the report status for the current trail
                report.resource_ids_status[trail_name] = has_lambda_logging

            if not lambda_logging_found:
                # No Lambda logging found across all trails
                report.resource_ids_status['No Lambda invoke logging enabled'] = False
            
            # Update the overall pass status
            report.passed = lambda_logging_found

        except (ClientError, BotoCoreError):
            # Handle AWS API errors
            report.resource_ids_status['Error checking CloudTrail configuration'] = False
        except Exception:
            # Handle unexpected exceptions
            report.resource_ids_status['Error checking CloudTrail configuration'] = False

        # Return the final report
        return report
