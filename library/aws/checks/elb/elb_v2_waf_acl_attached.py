"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-04-03
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class elb_v2_waf_acl_attached(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("elbv2")  # ALBs use elbv2
            waf_client = connection.client("wafv2")  # WAF API

            # Pagination for listing all ALBs
            albs = []
            next_marker = None

            while True:
                response = client.describe_load_balancers(Marker=next_marker) if next_marker else client.describe_load_balancers()
                albs.extend([lb for lb in response.get("LoadBalancers", []) if lb["Type"] == "application"])  # Filter only ALBs
                next_marker = response.get("NextMarker")

                if not next_marker:
                    break

            # If no ALBs exist, mark as NOT_APPLICABLE
            if not albs:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Application Load Balancers (ALBs) found.",
                    )
                )
                return report

            # Check each ALB for WAF association
            for alb in albs:
                lb_arn = alb["LoadBalancerArn"]
                lb_name = alb["LoadBalancerName"]
                resource = AwsResource(arn=lb_arn)

                try:
                    waf_response = waf_client.get_web_acl_for_resource(ResourceArn=lb_arn)
                    waf_attached = "WebACL" in waf_response

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.PASSED if waf_attached else CheckStatus.FAILED,
                            summary=f"WAF ACL {'attached' if waf_attached else 'not attached'} to ALB {lb_name}."
                        )
                    )

                    if not waf_attached:
                        report.status = CheckStatus.FAILED

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error checking WAF ACL for ALB {lb_name}: {str(e)}",
                            exception=str(e),
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving ALBs: {str(e)}",
                    exception=str(e),
                )
            )

        return report
