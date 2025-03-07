"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
import logging

from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class cloudfront_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize CloudFront client and report
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

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
                distribution_arn = distribution['ARN']

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
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.FAILED,
                            summary=f"{distribution_id} Access Logging: {'Enabled' if status else 'Disabled'}"
                        )
                    )

                    if not status:
                        report.status = CheckStatus.FAILED  # Mark as failed if any distribution does not have logging enabled

                else:
                    # If no logging configuration found, consider this as disabled
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=distribution_arn),
                            status=CheckStatus.FAILED,
                            summary=f"{distribution_id} Access Logging: Disabled"
                        )
                    )
                    report.status = CheckStatus.FAILED  # If there's no logging configuration at all, mark as failed

        except Exception as e:
            logging.error(f"Error while fetching CloudFront distribution config: {e}")
            report.status = CheckStatus.FAILED
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.FAILED,
                    summary=f"Error while fetching CloudFront distribution config",
                    exception=str(e)
                )
            )

        return report
