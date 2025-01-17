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
        # Initialize the API Gateway client
        apigw_client = connection.client('apigateway')

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

            # Check each API and its stages for WAFv2 ACL attachment or missing stages
            for api in apis:
                api_id = api['id']
                api_name = api.get('name', 'Unnamed API')

                # Fetch stages for the current API
                stages_response = apigw_client.get_stages(restApiId=api_id)
                stages = stages_response.get('item', [])

                if not stages:
                    # If no stages are present, set resource_ids_status to False
                    report.resource_ids_status[f"{api_name} has no stages."] = False
                    report.status = ResourceStatus.FAILED
                    continue

                api_has_waf = False

                for stage in stages:
                    stage_name = stage['stageName']
                    web_acl_id = stage.get('webAclArn')

                    if web_acl_id:
                        api_has_waf = True
                        resource_id = f"{api_name}/{stage_name}"
                        report.resource_ids_status[f"{resource_id} has WAF attached."] = True
                    else:
                        resource_id = f"{api_name}/{stage_name}"
                        report.resource_ids_status[f"{resource_id} has no WAF attached."] = False

                if not api_has_waf:
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            report.status = ResourceStatus.FAILED
            report.resource_ids_status["API Gateway listing error occurred."] = False

        return report
