import boto3

from framework.engine.entities.report.check_model import CheckReport
from framework.engine.entities.check.check import Check


class elb_logging_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('elb')
        res = client.describe_load_balancers()
        
        load_balancers = res['LoadBalancerDescriptions']
        
        report = CheckReport(name=__name__)
        
        for lb in load_balancers:
            lb_name = lb['LoadBalancerName']

            res = client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
            lb_attributes = res['LoadBalancerAttributes']

            print(f'lb_attributes = {lb_attributes}')

            report.passed = False
            report.resource_ids_status[lb_name] = False

            for attr in lb_attributes['LoadBalancerAttributes']:
                if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true':
                    report.passed = True
                    report.resource_ids_status[lb_name] = True

        return report
