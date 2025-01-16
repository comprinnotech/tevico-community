"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class elb_v2_logging_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('elbv2')
        paginator = client.get_paginator('describe_load_balancers')
        
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Iterate over all ALBs and NLBs
        for page in paginator.paginate():
            load_balancers = page['LoadBalancers']
            for lb in load_balancers:
                lb_arn = lb['LoadBalancerArn']
                
                # Get ELBv2 attributes to check logging
                attributes = client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)['Attributes']
                
                # Check if access logging is enabled
                logging_enabled = any(attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true' for attr in attributes)
                
                if logging_enabled:
                    report.resource_ids_status[lb_arn] = True
                else:
                    report.resource_ids_status[lb_arn] = False
                    report.status = ResourceStatus.FAILED

        return report
