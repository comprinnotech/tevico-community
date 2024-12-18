"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-15
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudfront_distributions_https_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('cloudfront')
        report = CheckReport(name=__name__)
        report.passed = True
        distributions = client.list_distributions()
        
        if ('DistributionList' in distributions and 
            'Items' in distributions['DistributionList'] and 
            distributions['DistributionList']['Items']):
            
            for distribution in distributions['DistributionList']['Items']:
                distribution_id = distribution['Id']
                default_cache_behavior = distribution.get('DefaultCacheBehavior', {})
                viewer_protocol_policy = default_cache_behavior.get('ViewerProtocolPolicy', '')
                if viewer_protocol_policy != 'redirect-to-https' and viewer_protocol_policy != 'https-only':
                    report.resource_ids_status[distribution_id] = False
                    report.passed = False
                else:
                    report.resource_ids_status[distribution_id] = True

        return report
