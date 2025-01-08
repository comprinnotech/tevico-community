import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class apigateway_restapi_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('apigateway')
        apis = client.get_rest_apis()['items']
        for api in apis:
            api_name = api['name']
            logging = api['endpointConfiguration']['types']
            if 'REGIONAL' in logging:
                report.status = True
                report.resource_ids_status[api_name] = True
            else:
                report.status = False
                report.resource_ids_status[api_name] = False
        return report

