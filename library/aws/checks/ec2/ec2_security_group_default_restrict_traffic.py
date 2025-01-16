"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_security_group_default_restrict_traffic(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('ec2')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Fetch all security groups with pagination
            security_groups = []
            next_token = None
            while True:
                if next_token:
                    response = client.describe_security_groups(NextToken=next_token)
                else:
                    response = client.describe_security_groups()
                security_groups.extend(response.get('SecurityGroups', []))
                next_token = response.get('NextToken')
                if not next_token:
                    break

            # Check each security group for default groups in all VPCs
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                vpc_id = sg.get('VpcId', 'N/A')

                # Only process default security groups
                if sg_name == 'default':
                    ingress_rules = sg.get('IpPermissions', [])
                    egress_rules = sg.get('IpPermissionsEgress', [])

                    if not ingress_rules and not egress_rules:
                        report.resource_ids_status[
                            f"{sg_id} (default SG) in VPC {vpc_id} is properly restricted"
                        ] = True
                    else:
                        report.resource_ids_status[
                            f"{sg_id} (default SG) in VPC {vpc_id} allows traffic"
                        ] = False
                        report.status = ResourceStatus.FAILED

        except Exception as e:
            report.resource_ids_status["Error fetching security groups"] = False
            report.status = ResourceStatus.FAILED

        return report