"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class ec2_network_acl_allow_ingress_tcp_port_22(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('ec2')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Pagination to get all network ACLs
            acls = []
            next_token = None

            while True:
                if next_token:
                    response = client.describe_network_acls(NextToken=next_token)
                else:
                    response = client.describe_network_acls()

                acls.extend(response.get('NetworkAcls', []))
                next_token = response.get('NextToken', None)

                if not next_token:
                    break

            # Define the TCP protocol and port to check
            tcp_protocol = "6"
            check_port = 22

            # Check each network ACL for rules allowing ingress on port 22
            for acl in acls:
                acl_id = acl['NetworkAclId']
                acl_allows_ingress = False

                for entry in acl['Entries']:
                    if entry['Egress']:  # Skip egress rules
                        continue

                    if entry.get('CidrBlock') == '0.0.0.0/0' and entry.get('RuleAction') == "allow":
                        if entry.get('Protocol') in [tcp_protocol, '-1']:  # Check TCP protocol or all protocols
                            port_range = entry.get('PortRange')
                            if not port_range or (port_range['From'] <= check_port <= port_range['To']):
                                acl_allows_ingress = True
                                break

                # Record the result for this ACL
                if acl_allows_ingress:
                    report.resource_ids_status[f"{acl_id} allows ingress on port 22 from 0.0.0.0/0"] = False
                    report.status =ResourceStatus.FAILED
                else:
                    report.resource_ids_status[f"{acl_id} does not allow ingress on port 22 from 0.0.0.0/0"] = True

        except Exception as e:
            report.resource_ids_status["Network ACL listing error occurred."] = False
            report.status =ResourceStatus.FAILED

        return report
