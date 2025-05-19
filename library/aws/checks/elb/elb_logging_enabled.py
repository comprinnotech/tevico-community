"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-03
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class elb_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("elb")
            account_id = connection.client("sts").get_caller_identity()["Account"]
            region = client.meta.region_name

            # Pagination for listing all ELBs
            load_balancers = []
            next_token = None

            while True:
                response = client.describe_load_balancers(Marker=next_token) if next_token else client.describe_load_balancers()
                load_balancers.extend(response.get("LoadBalancerDescriptions", []))
                next_token = response.get("NextMarker")

                if not next_token:
                    break

            # If no ELBs exist, mark as NOT_APPLICABLE
            if not load_balancers:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Classic Load Balancer found."
                    )
                )
                return report

            # Iterate over all ELBs to check logging status
            for lb in load_balancers:
                print(lb)  # Debugging: Print the load balancer details
                lb_name = lb.get("LoadBalancerName", "N/A")
                lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb_name}"
                resource = AwsResource(arn=lb_arn)

                try:
                    # Retrieve ELB attributes
                    attributes = client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
                    access_logs = attributes.get("LoadBalancerAttributes", {}).get("AccessLog", {})
                    logging_enabled = access_logs.get("Enabled", False)

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.PASSED if logging_enabled else CheckStatus.FAILED,
                            summary=f"Access logging {'enabled' if logging_enabled else 'not enabled'} for Classic Load Balancer {lb_name}."
                        )
                    )

                    if not logging_enabled:
                        report.status = CheckStatus.FAILED  # Mark overall status as FAILED if any ELB has logging disabled

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking logging for Classic Load Balancer {lb_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching Classic Load Balancer data: {str(e)}",
                    exception=str(e)
                )
            )

        return report
