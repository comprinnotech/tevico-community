"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-10
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class elb_waf_acl_attached(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('elbv2')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        # Get all ALBs
        paginator = client.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            load_balancers = page['LoadBalancers']
            for lb in load_balancers:
                lb_arn = lb['LoadBalancerArn']
                
                # Check if a WAF ACL is attached to the ALB
                try:
                    waf_client = connection.client('wafv2')
                    waf_association = waf_client.get_web_acl_for_resource(ResourceArn=lb_arn)
                    
                    if 'WebACL' in waf_association:
                        report.resource_ids_status[lb_arn] = True
                    else:
                        report.resource_ids_status[lb_arn] = False
                        report.status = ResourceStatus.FAILED
                except waf_client.exceptions.WAFNonexistentItemException:
                    # No WAF ACL attached
                    report.resource_ids_status[lb_arn] = False
                    report.status = ResourceStatus.FAILED

        return report
