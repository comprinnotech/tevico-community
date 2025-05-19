"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-13
"""
import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class networkfirewall_multi_az_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize Network Firewall client
        client = connection.client("network-firewall")
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Pagination for listing all firewalls
            firewalls = []
            next_token = None

            while True:
                response = client.list_firewalls(NextToken=next_token) if next_token else client.list_firewalls()
                firewalls.extend(response.get("Firewalls", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no firewalls exist, mark as NOT_APPLICABLE
            if not firewalls:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No Network Firewall resources found.",
                    )
                )
                return report

            # Check each firewall for Multi-AZ configuration
            for firewall in firewalls:
                # Fetch firewall details
                firewall_name = firewall["FirewallName"]
                firewall_details = client.describe_firewall(FirewallName=firewall_name)
                firewall_arn = firewall_details["Firewall"]["FirewallArn"]

                try:
                    subnet_mappings = firewall_details["Firewall"].get("SubnetMappings", [])
                    is_multi_az = len(subnet_mappings) > 1

                    if is_multi_az:
                        summary = f"Multi-AZ is enabled for Network Firewall {firewall_name}."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"Multi-AZ is not enabled for Network Firewall {firewall_name}."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED  # At least one firewall is non-compliant

                    # Append result to report
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=firewall_arn),
                            status=status,
                            summary=summary,
                        )
                    )


                except Exception as e:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=firewall_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving firewall details for {firewall_name}.",
                            exception=str(e),
                        )
                    )
                    report.status = CheckStatus.UNKNOWN

        except Exception as e:
            # Handle errors in firewall listing
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary="Error retrieving firewall list.",
                    exception=str(e),
                )
            )

        return report
