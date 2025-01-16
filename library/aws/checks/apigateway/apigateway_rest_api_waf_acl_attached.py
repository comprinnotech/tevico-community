"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-01-13
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class apigateway_rest_api_waf_acl_attached(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:

        # Initialize the API Gateway and WAFv2 clients
        apigw_client = connection.client('apigateway')
        wafv2_client = connection.client('wafv2')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Pagination to get all REST APIs
            apis = []
            next_token = None

            while True:
                if next_token:
                    response = apigw_client.get_rest_apis(position=next_token)
                else:
                    response = apigw_client.get_rest_apis()

                apis.extend(response.get('items', []))
                next_token = response.get('position', None)

                if not next_token:
                    break

            # Check each API and its stages for WAFv2 ACL attachment
            for api in apis:
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')

                # Fetch stages for the current API
                stages_response = apigw_client.get_stages(restApiId=api_id)
                stages = stages_response.get('item', [])

                api_has_waf = False

                for stage in stages:
                    stage_name = stage['stageName']
                    stage_arn = f"arn:aws:apigateway:{connection.region_name}::/restapis/{api_id}/stages/{stage_name}"

                    try:
                        # Check if a WAFv2 ACL is attached to the stage
                        wafv2_response = wafv2_client.get_web_acl_for_resource(ResourceArn=stage_arn)

                        if wafv2_response.get('WebACL'):
                            api_has_waf = True
                            resource_id = f"{api_name}/{stage_name}"
                            if wafv2_response.get('WebACL'):
                                api_has_waf = True
                                report.resource_ids_status[f"{resource_id} has WAF attached."] = True
                            else:
                                report.resource_ids_status[f"{resource_id} has no WAF attached."] = False
                            report.resource_ids_status[f"{resource_id} has WAF attached."] = True
                        else:
                            resource_id = f"{api_name}/{stage_name}"
                            report.resource_ids_status[f"{resource_id} has no WAF attached."] = False

                    except wafv2_client.exceptions.WAFNonexistentItemException:
                        # Record the status for this stage as not having a WAF ACL
                        resource_id = f"{api_name}/{stage_name}"
                        report.resource_ids_status[f"{resource_id} has no WAF attached."] = False

                if not api_has_waf:
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            report.resource_ids_status["API Gateway listing error occurred."] = False
            report.status = ResourceStatus.FAILED

        return report
