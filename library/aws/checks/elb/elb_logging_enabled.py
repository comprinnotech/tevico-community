"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-1-4
"""

"""
Check: ELB Logging Enabled
Description: Verifies if Elastic Load Balancers have logging enabled
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class elb_logging_enabled(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def check_lb_logging(self, client, lb_type: str, lb_arn: str, lb_name: str) -> tuple:
        """
        Check logging configuration for a specific load balancer
        Args:
            client: ELB client
            lb_type: Load balancer type (application/network/classic)
            lb_arn: Load balancer ARN
            lb_name: Load balancer name
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        try:
            if lb_type == 'classic':
                attrs = client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
                is_enabled = attrs.get('LoadBalancerAttributes', {}).get('AccessLog', {}).get('Enabled', False)
            else:
                attrs = client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                is_enabled = any(
                    attr['Key'] == 'access_logs.s3.enabled' and attr['Value'].lower() == 'true'
                    for attr in attrs.get('Attributes', [])
                )
            
            return is_enabled, f"{lb_type.capitalize()} LB {lb_name}: {'Logging enabled' if is_enabled else 'Logging disabled'}"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                return False, f"{lb_type.capitalize()} LB {lb_name}: Not found"
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the ELB logging check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            # Check classic load balancers
            elb = connection.client('elb')
            elbv2 = connection.client('elbv2')
            
            # Check classic ELBs
            try:
                classic_lbs = elb.describe_load_balancers().get('LoadBalancerDescriptions', [])
                for lb in classic_lbs:
                    is_compliant, message = self.check_lb_logging(
                        elb, 'classic', '', lb['LoadBalancerName']
                    )
                    report.resource_ids_status[message] = is_compliant
                    if not is_compliant:
                        report.passed = False
            except ClientError:
                pass

            # Check ALB/NLB
            try:
                v2_lbs = elbv2.describe_load_balancers().get('LoadBalancers', [])
                for lb in v2_lbs:
                    is_compliant, message = self.check_lb_logging(
                        elbv2, lb['Type'], lb['LoadBalancerArn'], lb['LoadBalancerName']
                    )
                    report.resource_ids_status[message] = is_compliant
                    if not is_compliant:
                        report.passed = False
            except ClientError:
                pass

            if not report.resource_ids_status:
                report.passed = False
                report.resource_ids_status["No load balancers found"] = False

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
