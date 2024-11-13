import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class opensearch_service_domains_audit_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('opensearch')
        res = client.list_domain_names()
        
        domain_names = res['DomainNames']
        
        report = CheckReport(name=__name__)
        
        for dn in domain_names:
            domain_name = dn['DomainName']
            res = client.describe_domain(DomainName=domain_name)
            domain = res['DomainStatus']
            report.passed = False
            report.resource_ids_status[domain_name] = False
            if domain['LogPublishingOptions']['Options']['AUDIT_LOGS']['Enabled']:
                report.passed = True
                report.resource_ids_status[domain_name] = True

        return report
    
