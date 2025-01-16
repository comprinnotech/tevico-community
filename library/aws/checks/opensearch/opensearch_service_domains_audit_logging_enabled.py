import boto3

from typing import Any
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


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
            report.status = ResourceStatus.FAILED
            report.resource_ids_status[domain_name] = False
            if domain['LogPublishingOptions']['Options']['AUDIT_LOGS']['Enabled']:
                report.status = ResourceStatus.PASSED
                report.resource_ids_status[domain_name] = True

        return report
    
