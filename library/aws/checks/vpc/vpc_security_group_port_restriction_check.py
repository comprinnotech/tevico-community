"""
AUTHOR: Sheikh Aafaq Rashid
EMAIL: aafaq.rashid@comprinno.net
DATE: 2025-04-15
UPDATED: 2025-04-16
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tevico.engine.entities.report.check_model import GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check

class vpc_security_group_port_restriction_check(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Check if security groups allow unrestricted access to high-risk ports.
        
        This check aligns with AWS Security Hub control EC2.19, which identifies security groups
        that allow unrestricted access (0.0.0.0/0 or ::/0) to high-risk ports.
        
        Args:
            connection: boto3 Session object for AWS API calls
            
        Returns:
            CheckReport: Report containing the results of the check
        """
        # Initialize the check report
        report = CheckReport(name=__name__)
        report.resource_ids_status = []

        try:
            # Set up AWS client for EC2
            ec2_client = connection.client('ec2')
            
            # Retrieve all security groups using pagination
            security_groups = []
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                security_groups.extend(page.get("SecurityGroups", []))

            # Handle case where no security groups are found
            if not security_groups:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No security groups found."
                    )
                )
                return report

            # High-risk ports to check for unrestricted access
            # Based on AWS Security Hub control EC2.19
            # https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-19
            restricted_ports = {
                20, 21,  # FTP
                22,      # SSH
                23,      # Telnet
                25,      # SMTP
                110,     # POP3
                135,     # RPC
                143,     # IMAP
                445,     # SMB
                1433, 1434,  # SQL Server
                3000,    # Development servers
                3306,    # MySQL
                3389,    # RDP
                4333,
                5000,    # Various applications
                5432,    # PostgreSQL
                5500,
                5601,    # Kibana
                8080, 8088, 8888,  # Alternative HTTP ports
                9200, 9300  # Elasticsearch
            }

            # Evaluate each security group
            for sg in security_groups:
                group_id = sg.get("GroupId")
                group_name = sg.get("GroupName", "")
                
                # Security groups don't have traditional ARNs, use the ID as resource identifier
                resource = GeneralResource(name=group_id)
                
                # Get inbound rules
                inbound_rules = sg.get("IpPermissions", [])
                
                # Track violations for this security group
                violations = []
                
                # Check each inbound rule
                for rule in inbound_rules:
                    # Skip rules without port information (e.g., ICMP rules)
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    if from_port is None or to_port is None:
                        continue
                    
                    # Check for public access (0.0.0.0/0 or ::/0)
                    ip_ranges = rule.get("IpRanges", [])
                    ipv6_ranges = rule.get("Ipv6Ranges", [])
                    
                    public_ipv4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)
                    public_ipv6 = any(r.get("CidrIpv6") == "::/0" for r in ipv6_ranges)
                    
                    # Skip if not publicly accessible
                    if not (public_ipv4 or public_ipv6):
                        continue
                    
                    # First check if any high-risk port is in the range (quick check)
                    has_restricted_port = False
                    for port in restricted_ports:
                        if from_port <= port <= to_port:
                            has_restricted_port = True
                            break
                    
                    if not has_restricted_port:
                        continue
                    
                    # Identify which specific high-risk ports are exposed
                    exposed_ports = []
                    for port in restricted_ports:
                        if from_port <= port <= to_port:
                            exposed_ports.append(port)
                    
                    # Record the violation
                    cidr = "0.0.0.0/0" if public_ipv4 else "::/0"
                    if from_port == to_port:
                        violations.append(f"Inbound rule allows {cidr} access to high-risk port {from_port}")
                    else:
                        port_str = ", ".join(str(port) for port in exposed_ports)
                        violations.append(f"Inbound rule allows {cidr} access to port range {from_port}-{to_port}, exposing high-risk ports: {port_str}")
                
                # Record the evaluation result for this security group
                if violations:
                    summary = f"Security group {group_id} ({group_name}) has unrestricted access to high-risk ports:\n"
                    summary += "\n".join(f"- {v}" for v in violations)
                    
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.FAILED,
                            summary=summary
                        )
                    )
                else:
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=resource,
                            status=CheckStatus.PASSED,
                            summary=f"Security group {group_id} ({group_name}) properly restricts access to high-risk ports."
                        )
                    )
                
        except (BotoCoreError, ClientError) as e:
            # AWS API Exception Handling
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"AWS API request failed. Unable to verify security group configurations: {str(e)}",
                    exception=str(e)
                )
            )
        except Exception as e:
            # Global Exception Handling
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error checking security group configurations: {str(e)}",
                    exception=str(e)
                )
            )

        return report
