"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-02
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class elb_v2_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        # Initialize the ELBv2 client
        client = connection.client('elbv2')

        try:
            # Pagination to get all load balancers
            load_balancers = []
            next_token = None

            while True:
                response = client.describe_load_balancers(Marker=next_token) if next_token else client.describe_load_balancers()
                load_balancers.extend(response.get('LoadBalancers', []))
                next_token = response.get('NextMarker', None)

                if not next_token:
                    break

            # Check if any load balancers were found
            if not load_balancers:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No load balancers found."
                    )
                )
                return report

            # Iterate over all load balancers and check logging status
            for lb in load_balancers:
                lb_name = lb['LoadBalancerName']  # Extract ALB name
                lb_arn = lb['LoadBalancerArn']

                try:

                    # Get ELBv2 attributes to check logging
                    attributes = client.describe_load_balancer_attributes(LoadBalancerArn=lb['LoadBalancerArn'])['Attributes']

                    # Check if access logging is enabled
                    logging_enabled = any(
                        attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true'
                        for attr in attributes
                    )

                    # Record the result for this load balancer using ALB name
                    if logging_enabled:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=lb_arn),
                                status=CheckStatus.PASSED,
                                summary=f"{lb_name} has logging enabled."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=lb_arn),
                                status=CheckStatus.FAILED,
                                summary=f"{lb_name} has logging not enabled."
                            )
                        )
                #handle unexpected error for each load balancer
                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=lb_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error fetching attributes for {lb_name}.",
                            exception=str(e)
                        )
                    )
                    report.status = CheckStatus.UNKNOWN 

        except Exception as e:
            # Handle unexpected errors
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching load balancers.",
                    exception=str(e)
                )
            )
            report.status = CheckStatus.UNKNOWN

        return report
