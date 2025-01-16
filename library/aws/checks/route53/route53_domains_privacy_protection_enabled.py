"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class route53_domains_privacy_protection_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        
        route53domains_client = connection.client('route53domains', region_name="us-east-1")
        
       
        domains = route53domains_client.list_domains()['Domains']
      
       
        for domain_info in domains:
            domain_name = domain_info['DomainName']
            domain_detail = route53domains_client.get_domain_detail(DomainName=domain_name)
            

          
            if domain_detail.get('AdminPrivacy'):
                report.resource_ids_status[domain_name] = True
            else:
                report.resource_ids_status[domain_name] = False
                report.status = ResourceStatus.FAILED

        return report
