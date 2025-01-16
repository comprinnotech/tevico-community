"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class apigateway_waf_protection_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('apigateway')
        waf_client = connection.client('waf-regional')
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        
        try:
            # Retrieve all REST APIs
            apis = client.get_rest_apis()
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')
                
                # Get the stages for this API
                stages = client.get_stages(restApiId=api_id)
                
                api_protected = False
                for stage in stages['item']:
                    stage_arn = f"arn:aws:apigateway:{connection.region_name}::/restapis/{api_id}/stages/{stage['stageName']}"
                    
                    try:
                        # Get the WebACL associated with this stage
                        web_acl = waf_client.get_web_acl_for_resource(
                            ResourceArn=stage_arn
                        )
                        
                        if web_acl.get('WebACLSummary'):
                            api_protected = True
                            break
                            
                    except (waf_client.exceptions.WAFNonexistentItemException,
                           waf_client.exceptions.WAFInvalidParameterException):
                        continue
                
                report.resource_ids_status[api_name] = api_protected
                if not api_protected:
                    report.status = ResourceStatus.FAILED
                    
        except Exception as e:
            report.status = ResourceStatus.FAILED
            
        return report
