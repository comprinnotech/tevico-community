"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-09
"""
        
import boto3
from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check

class ec2_security_group_default_restrict_traffic(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('ec2')
        security_groups = client.describe_security_groups()['SecurityGroups']
        vpcs = client.describe_vpcs()['Vpcs']
        network_interfaces = client.describe_network_interfaces()['NetworkInterfaces']
        report.passed = True
        vpcs_in_use = {vpc['VpcId']: vpc for vpc in vpcs}
        sg_network_interfaces = {}
        for ni in network_interfaces:
            for group in ni['Groups']:
                sg_id = group['GroupId']
                if sg_id not in sg_network_interfaces:
                    sg_network_interfaces[sg_id] = []
                sg_network_interfaces[sg_id].append(ni['NetworkInterfaceId'])

        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            vpc_id = sg.get('VpcId')
            
            if sg_name == 'default':
                sg_in_use = vpc_id in vpcs_in_use  
                has_network_interfaces = sg_id in sg_network_interfaces and len(sg_network_interfaces[sg_id]) > 0                
                if sg_in_use and has_network_interfaces:
                    ingress_rules = sg.get('IpPermissions', [])
                    egress_rules = sg.get('IpPermissionsEgress', [])
                    if not ingress_rules and not egress_rules:
                        report.resource_ids_status[sg_id] = True
                    else:
                        report.resource_ids_status[sg_id] = False
                        report.passed = False
                else:
                    report.resource_ids_status[sg_id] = True

        return report
