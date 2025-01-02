"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-12
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class vpc_default_security_group_closed(Check):
    def _get_default_security_groups(self, ec2_client):
        """Get all default security groups for all VPCs"""
        try:
            # Get all VPCs
            vpcs = ec2_client.describe_vpcs()
            
            default_sgs = {}
            # For each VPC, get its default security group
            for vpc in vpcs.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                if not vpc_id:
                    continue
                
                # Get the default security group for this VPC
                response = ec2_client.describe_security_groups(
                    Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                        {'Name': 'group-name', 'Values': ['default']}
                    ]
                )
                
                # Store the security groups for this VPC
                default_sgs[vpc_id] = response.get('SecurityGroups', [])
                
            return default_sgs
        except (ClientError, BotoCoreError) as e:
            return None

    def _check_security_group_rules(self, security_group):
        """Check if security group has any rules"""
        # Check for inbound rules
        if security_group.get('IpPermissions', []):
            return False
            
        # Check for outbound rules
        if security_group.get('IpPermissionsEgress', []):
            return False
            
        return True

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            ec2_client = connection.client('ec2')
            
            # Get all default security groups
            vpc_security_groups = self._get_default_security_groups(ec2_client)
            
            if vpc_security_groups is None:
                report.passed = False
                report.resource_ids_status['ERROR'] = False
                return report
                
            if not vpc_security_groups:
                report.resource_ids_status['NO_VPCS'] = True
                return report

            # Check each VPC's default security group
            for vpc_id, security_groups in vpc_security_groups.items():
                if not security_groups:
                    # No default security group found for this VPC
                    report.resource_ids_status[f'vpc-{vpc_id}'] = False
                    report.passed = False
                    continue

                # Check rules in each security group
                for sg in security_groups:
                    sg_id = sg.get('GroupId', 'unknown')
                    is_closed = self._check_security_group_rules(sg)
                    
                    report.resource_ids_status[f'sg-{sg_id}'] = is_closed
                    if not is_closed:
                        report.passed = False

        except Exception as e:
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        return report

