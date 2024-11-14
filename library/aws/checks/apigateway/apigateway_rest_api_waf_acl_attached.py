"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class apigateway_rest_api_waf_acl_attached(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            # Initialize clients
            apigw_client = connection.client('apigateway')
            wafv2_client = connection.client('wafv2')
            
            # Get all REST APIs
            apis = apigw_client.get_rest_apis()
            
            for api in apis.get('items', []):
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')
                
                # Get all stages for this API
                stages = apigw_client.get_stages(restApiId=api_id)
                
                api_has_waf = False
                for stage in stages['item']:
                    stage_name = stage['stageName']
                    stage_arn = f"arn:aws:apigateway:{connection.region_name}::/restapis/{api_id}/stages/{stage_name}"
                    
                    try:
                        # Check WAFv2 associations
                        wafv2_response = wafv2_client.get_web_acl_for_resource(
                            ResourceArn=stage_arn
                        )
                        
                        if wafv2_response.get('WebACL'):
                            api_has_waf = True
                            break
                            
                    except wafv2_client.exceptions.WAFNonexistentItemException:
                        continue
                    except wafv2_client.exceptions.WAFInvalidParameterException:
                        continue
                    except Exception as e:
                        continue
                
                # Record the status for this API
                report.resource_ids_status[api_name] = api_has_waf
                
                # If any API doesn't have WAF, mark the overall check as failed
                if not api_has_waf:
                    report.passed = False
                    
        except Exception as e:
            report.passed = False
            
        return report
