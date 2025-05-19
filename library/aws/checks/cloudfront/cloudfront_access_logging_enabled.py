"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-01-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class cloudfront_access_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            distributions = []
            next_marker = None

            while True:
                response = client.list_distributions(Marker=next_marker) if next_marker else client.list_distributions()
                distributions.extend(response.get('DistributionList', {}).get('Items', []))
                next_marker = response.get('NextMarker')
                if not next_marker:
                    break

            if not distributions:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                        ResourceStatus(
                            resource=GeneralResource(name=""),
                            status=CheckStatus.NOT_APPLICABLE,
                            summary=f"No distributions found.",
                          
                        )
                    )
                

            for distribution in distributions:
                distribution_id = distribution['Id']
                distribution_arn = distribution['ARN']
                resource = AwsResource(arn=distribution_arn)

                try:
                    dist_config = client.get_distribution_config(Id=distribution_id)
                    distribution_config = dist_config.get('DistributionConfig', {})

                    legacy_logging_config = distribution_config.get('Logging', {})
                    logging_enabled = legacy_logging_config.get('Enabled', False)

                    realtime_log_config_arn = distribution_config.get(
                        'DefaultCacheBehavior', {}).get('RealtimeLogConfigArn')

                    if logging_enabled or realtime_log_config_arn:
                        status = CheckStatus.PASSED
                        summary = f"Access Logging is ENABLED for {distribution_id}."
                    else:
                        status = CheckStatus.FAILED
                        summary = f"Access Logging is DISABLED for {distribution_id}."
                        report.status = CheckStatus.FAILED

                    report.resource_ids_status.append(
                        ResourceStatus(resource=resource, status=status, summary=summary)
                    )

                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving config for {distribution_id}.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error while fetching CloudFront distributions",
                    exception=str(e)
                )
            )

        return report
