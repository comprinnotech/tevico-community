"""
AUTHOR: Deepak Puri
EMAIL: deepak.puri@comprinno.net
DATE: 2024-10-09
"""

import boto3
from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check

class ec2_network_acl_allow_ingress_tcp_port_22(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('ec2')
        acls = client.describe_network_acls()['NetworkAcls']
        
        tcp_protocol = "6"
        check_port = 22
        report.passed = True   

        for acl in acls:
            acl_id = acl['NetworkAclId']
            acl_allows_ingress = False
            
            for entry in acl['Entries']:
                if entry['Egress']:  
                    continue
                if entry['CidrBlock'] != '0.0.0.0/0' or entry['RuleAction'] != "allow": 
                    continue
                if entry['Protocol'] != tcp_protocol and entry['Protocol'] != '-1': 
                    continue

                port_range = entry.get('PortRange')
                if port_range and port_range['From'] <= check_port <= port_range['To']:
                    acl_allows_ingress = True
                    break
                if entry['Protocol'] == '-1': 
                    acl_allows_ingress = True
                    break
            
            report.resource_ids_status[acl_id] = not acl_allows_ingress
            if acl_allows_ingress:
                report.passed = False
        
        return report

