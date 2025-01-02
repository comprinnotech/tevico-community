"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudfront_cloudwatch_logging_enabled(Check):

    # Fetch the list of CloudFront distributions to evaluate logging status for
    def _get_distributions(self, client):
        response = client.list_distributions()
        
        # Extracts and returns the list of distributions if available
        return response.get('DistributionList', {}).get('Items', [])

    # Check if CloudWatch logging is enabled for a specific distribution
    def _check_cloudwatch_logging_enabled(self, client, distribution_id):
        try:
            # Retrieve the configuration for the specified distribution
            response = client.get_distribution(Id=distribution_id)
            distribution_config = response['Distribution']['DistributionConfig']
            
            # Extract the logging configuration from the distribution configuration
            logging_config = distribution_config.get('Logging', {})
            
            # Check if logging is enabled and ensure it is configured for CloudWatch Logs
            return (logging_config.get('Enabled', False) and 
                   logging_config.get('DestinationType') == 'CWL')  # Verify if DestinationType is set to CWL
            
        except ClientError:
            # Return False if the distribution configuration could not be fetched
            return False

    # Execute the main logic to evaluate CloudWatch logging status across all distributions
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Retrieve all CloudFront distributions
            distributions = self._get_distributions(client)

            # Handle the case where no distributions are found in the account
            if not distributions:
                # Mark the status for 'NoDistributions' as True and set the check as passed
                report.resource_ids_status['NoDistributions'] = True
                return report

            # Loop through each distribution to check if CloudWatch logging is enabled
            for distribution in distributions:
                try:
                    distribution_id = distribution['Id']
                    
                    # Check if CloudWatch logging is enabled for the distribution
                    cloudwatch_enabled = self._check_cloudwatch_logging_enabled(client, distribution_id)
                    report.resource_ids_status[distribution_id] = cloudwatch_enabled

                    # If any distribution has logging disabled, mark the check as failed
                    if not cloudwatch_enabled:
                        report.passed = False

                except KeyError:
                    # If any key error occurs while processing the distribution, mark the check as failed
                    report.passed = False
                    return report

        # Catch specific errors related to CloudFront and other potential exceptions
        except (ClientError, BotoCoreError, Exception):
            report.passed = False
            return report

        # Return the report with the final check status
        return report
