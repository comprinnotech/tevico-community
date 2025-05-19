"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-03
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check

class elb_ssl_listeners_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("elb")
            account_id = connection.client("sts").get_caller_identity()["Account"]
            region = client.meta.region_name

            # Pagination for listing all Classic Load Balancers
            load_balancers = []
            next_token = None

            while True:
                response = client.describe_load_balancers(Marker=next_token) if next_token else client.describe_load_balancers()
                load_balancers.extend(response.get("LoadBalancerDescriptions", []))
                next_token = response.get("NextMarker")

                if not next_token:
                    break

            # If no Classic Load Balancers exist, mark as NOT_APPLICABLE
            if not load_balancers:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Classic Load Balancers found."
                    )
                )
                return report

            # Iterate over all Classic Load Balancers to check SSL listener status
            for lb in load_balancers:
                lb_name = lb.get("LoadBalancerName", "N/A")
                lb_arn = f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{lb_name}"
                resource = AwsResource(arn=lb_arn)

                try:
                    listeners = lb.get("ListenerDescriptions", [])
                    ssl_enabled = any(
                        listener["Listener"]["Protocol"] in ["HTTPS", "SSL"]
                        for listener in listeners
                    )

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.PASSED if ssl_enabled else CheckStatus.FAILED,
                            summary=f"SSL listeners {'enabled' if ssl_enabled else 'not enabled'} for load balancer {lb_name}."
                        )
                    )

                    if not ssl_enabled:
                        report.status = CheckStatus.FAILED  # Mark overall status as FAILED if any ELB lacks SSL

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking listeners for load balancer {lb_name}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error accessing ELB load balancers: {str(e)}",
                    exception=str(e)
                )
            )

        return report
