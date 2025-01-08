"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-1-4
"""
"""
Check: ELB SSL Listeners Enabled
Description: Verifies if Elastic Load Balancers have SSL/TLS listeners configured
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class elb_ssl_listeners_enabled(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)
        self.ssl_protocols = {'HTTPS', 'TLS', 'SSL'}

    def check_classic_lb(self, client, lb_name: str) -> tuple:
        """
        Check SSL listeners for classic load balancer
        Args:
            client: Classic ELB client
            lb_name: Load balancer name
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        try:
            listeners = client.describe_load_balancers(
                LoadBalancerNames=[lb_name]
            )['LoadBalancerDescriptions'][0]['ListenerDescriptions']
            
            has_ssl = any(
                listener['Listener'].get('Protocol', '').upper() in self.ssl_protocols
                for listener in listeners
            )
            return has_ssl, f"Classic LB {lb_name}: {'Has' if has_ssl else 'Missing'} SSL listener"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                return False, f"Classic LB {lb_name}: Not found"
            raise

    def check_v2_lb(self, client, lb_arn: str, lb_name: str, lb_type: str) -> tuple:
        """
        Check SSL listeners for ALB/NLB
        Args:
            client: ELBv2 client
            lb_arn: Load balancer ARN
            lb_name: Load balancer name
            lb_type: Load balancer type
        Returns:
            tuple: (is_compliant: bool, message: str)
        """
        try:
            listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get('Listeners', [])
            has_ssl = any(
                listener.get('Protocol', '').upper() in self.ssl_protocols
                for listener in listeners
            )
            return has_ssl, f"{lb_type} {lb_name}: {'Has' if has_ssl else 'Missing'} SSL listener"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'LoadBalancerNotFound':
                return False, f"{lb_type} {lb_name}: Not found"
            raise

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the SSL listener check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            elb = connection.client('elb')
            elbv2 = connection.client('elbv2')
            
            # Check classic ELBs
            try:
                classic_lbs = elb.describe_load_balancers().get('LoadBalancerDescriptions', [])
                for lb in classic_lbs:
                    is_compliant, message = self.check_classic_lb(elb, lb['LoadBalancerName'])
                    report.resource_ids_status[message] = is_compliant
                    if not is_compliant:
                        report.passed = False
            except ClientError:
                pass

            # Check ALB/NLB
            try:
                v2_lbs = elbv2.describe_load_balancers().get('LoadBalancers', [])
                for lb in v2_lbs:
                    is_compliant, message = self.check_v2_lb(
                        elbv2, lb['LoadBalancerArn'], lb['LoadBalancerName'], lb['Type']
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
