"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, CheckStatus, AwsResource, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_security_group_default_restrict_traffic(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("ec2")

        # Initialize check report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            # Custom pagination approach for fetching security groups
            security_groups = []
            next_token = None

            while True:
                response = client.describe_security_groups(NextToken=next_token) if next_token else client.describe_security_groups()
                security_groups.extend(response.get("SecurityGroups", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # Process each security group
            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                vpc_id = sg.get("VpcId", "N/A")

                # Check only default security groups
                if sg_name == "default":
                    ingress_rules = sg.get("IpPermissions", [])
                    egress_rules = sg.get("IpPermissionsEgress", [])

                    if not ingress_rules and not egress_rules:
                        summary = f"Default security group {sg_id} in VPC {vpc_id} is properly restricted."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"Default security group {sg_id} in VPC {vpc_id} allows traffic."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED

                    # Append result to report
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=f"arn:aws:ec2:::security-group/{sg_id}"),
                            status=status,
                            summary=summary
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching security groups: {str(e)}",
                    exception=str(e)
                )
            )

        return report
