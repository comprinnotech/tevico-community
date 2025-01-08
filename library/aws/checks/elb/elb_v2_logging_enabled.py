"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-1-4
"""

"""
Check: ELBv2 Logging Enabled
Description: Verifies if Application and Network Load Balancers have logging enabled
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class elb_v2_logging_enabled(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def check_lb_logging(self, client, lb_arn: str, lb_name: str, lb_type: str) -> tuple:
        """
        Check logging configuration for a specific load balancer
        Args:
            client: ELBv2 client
            lb_arn: Load balancer ARN
            lb_name: Load balancer name
            lb_type: Load balancer type (application/network)
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        try:
            attrs = client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            is_enabled = any(
                attr['Key'] == 'access_logs.s3.enabled' and attr['Value'].lower() == 'true'
                for attr in attrs.get('Attributes', [])
            )
            
            return is_enabled, f"{lb_type} LB {lb_name}: {'Logging enabled' if is_enabled else 'Logging disabled'}"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                return False, f"{lb_type} LB {lb_name}: Not found"
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the ELBv2 logging check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            elbv2 = connection.client('elbv2')
            
            try:
                load_balancers = elbv2.describe_load_balancers().get('LoadBalancers', [])
                
                for lb in load_balancers:
                    # Skip Gateway Load Balancers as they don't support access logging
                    if lb['Type'].upper() == 'GATEWAY':
                        continue
                        
                    is_compliant, message = self.check_lb_logging(
                        elbv2, lb['LoadBalancerArn'], lb['LoadBalancerName'], lb['Type']
                    )
                    report.resource_ids_status[message] = is_compliant
                    if not is_compliant:
                        report.passed = False
                        
                if not report.resource_ids_status:
                    report.resource_ids_status["No eligible load balancers found"] = True
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'LoadBalancerNotFound':
                    raise

        except ClientError as e:
            report.passed = False
            report.resource_ids_status[f"AWS Error: {e.response['Error']['Code']}"] = False
        except Exception as e:
            report.passed = False
            report.resource_ids_status[f"Unexpected Error: {str(e)}"] = False

        return report
