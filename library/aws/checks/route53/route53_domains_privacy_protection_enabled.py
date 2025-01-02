"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-10
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class route53_domains_privacy_protection_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize the report with the name of the check and default status
        report = CheckReport(name=__name__)
        report.passed = True
        report.resource_ids_status = {}

        try:
            # Create a client for Route 53 Domains in the us-east-1 region
            route53domains_client = connection.client('route53domains', region_name="us-east-1")
            
            # Retrieve the list of all domains in the account
            domains = route53domains_client.list_domains()['Domains']

            # If no domains are found, mark the check as failed
            if not domains:
                report.passed = False
                report.resource_ids_status['No Route53 Domains found'] = False
                return report

            # Iterate through each domain and check if privacy protection is enabled
            for domain_info in domains:
                domain_name = domain_info['DomainName']

                try:
                    # Retrieve domain details
                    domain_detail = route53domains_client.get_domain_detail(DomainName=domain_name)

                    # Check if AdminPrivacy is enabled for the domain
                    if domain_detail.get('AdminPrivacy'):
                        report.resource_ids_status[domain_name] = True
                        
                    else:
                        
                        # Mark the domain as failing if AdminPrivacy is not enabled                       
                        report.resource_ids_status[domain_name] = False
                        report.passed = False

                except (ClientError, BotoCoreError, Exception):
                    
                    # Handle errors when retrieving domain details                   
                    report.passed = False
                    report.resource_ids_status[domain_name] = False

        except (ClientError, BotoCoreError, Exception):
                       
            # Handle errors when retrieving the list of domains          
            report.passed = False
            report.resource_ids_status['No Route53 Domains found'] = False

        # Return the final report with the results of the check
        return report
