"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudfront_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudFront client and report
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # List all distributions
            distributions = []
            next_marker = None

            while True:
                response = client.list_distributions(Marker=next_marker) if next_marker else client.list_distributions()
                distributions.extend(response.get('DistributionList', {}).get('Items', []))
                next_marker = response.get('NextMarker')
                if not next_marker:
                    break

            # Get and log the configuration of each distribution
            for distribution in distributions:
                distribution_id = distribution['Id']

                # Get the distribution configuration using get_distribution_config
                dist_config = client.get_distribution_config(Id=distribution_id)
                distribution_config = dist_config.get('DistributionConfig', {})

                # Check for legacy logging configuration
                legacy_logging_config = distribution_config.get('Logging', {})
                logging_enabled = legacy_logging_config.get('Enabled', False)

                # Check for real-time log configuration
                realtime_log_config_arn = distribution_config.get(
                    'DefaultCacheBehavior', {}).get('RealtimeLogConfigArn')

                # Log the result
                if legacy_logging_config or realtime_log_config_arn:
                    status = logging_enabled or bool(realtime_log_config_arn)
                    report.resource_ids_status[f"{distribution_id} Access Logging: {'Enabled' if status else 'Disabled'}"] = status

                    if not status:
                        report.status = ResourceStatus.FAILED  # Mark as failed if any distribution does not have logging enabled

                else:
                    # If no logging configuration found, consider this as disabled
                    report.resource_ids_status[f"{distribution_id} Access Logging: Disabled"] = False
                    report.status = ResourceStatus.FAILED  # If there's no logging configuration at all, mark as failed

        except Exception as e:
            logging.error(f"Error while fetching CloudFront distribution config: {e}")
            report.status = ResourceStatus.FAILED
            report.resource_ids_status = {}

        return report
