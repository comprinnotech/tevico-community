"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class elb_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('elb')
        paginator = client.get_paginator('describe_load_balancers')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Iterate over all ELBs
        for page in paginator.paginate():
            load_balancers = page['LoadBalancerDescriptions']
            for lb in load_balancers:
                lb_name = lb['LoadBalancerName']
                
                # Get ELB attributes to check logging
                lb_attributes = client.describe_load_balancer_attributes(LoadBalancerName=lb_name)['LoadBalancerAttributes']
                
                # Check if access logging is enabled
                access_logs = lb_attributes.get('AccessLog', {})
                if access_logs.get('Enabled', False):
                    report.resource_ids_status[lb_name] = True
                else:
                    report.resource_ids_status[lb_name] = False
                    report.status = ResourceStatus.FAILED

        return report



