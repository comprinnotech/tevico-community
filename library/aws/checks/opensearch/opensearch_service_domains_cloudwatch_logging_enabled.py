import boto3

from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class opensearch_service_domains_cloudwatch_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('opensearch')
        res = client.list_domain_names()
        
        domain_names = res['DomainNames']
        
        report = CheckReport(name=__name__)
        
        log_publishing_options = [
            'INDEX_SLOW_LOGS',
            'SEARCH_SLOW_LOGS',
            'ES_APPLICATION_LOGS'
        ]
        
        for dn in domain_names:
            domain_name = dn['DomainName']
            res = client.describe_domain_config(DomainName=domain_name)
            for log_option in log_publishing_options:
                report.status = ResourceStatus.FAILED
                report.resource_ids_status[domain_name] = False
                if res['DomainConfig']['LogPublishingOptions'][log_option]['Enabled']:
                    report.status = ResourceStatus.PASSED
                    report.resource_ids_status[domain_name] = True

        return report
        
