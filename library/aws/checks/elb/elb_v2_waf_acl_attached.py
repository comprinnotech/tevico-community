"""
AUTHOR: RONIT CHAUHAN
EMAIL: ronit.chauhan@comprinno.net
DATE: 2024-1-4
"""

"""
Check: ELBv2 WAF ACL Attached
Description: Verifies if Application Load Balancers have WAF ACLs attached
"""
import boto3
from botocore.exceptions import ClientError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class elb_v2_waf_acl_attached(Check):
    def __init__(self, metadata=None):
        """Initialize check configuration"""
        super().__init__(metadata)

    def get_waf_associations(self, wafv2_client) -> dict:
        """
        Get WAF ACL associations for all resources
        Args:
            wafv2_client: WAFv2 client
        Returns:
            dict: Dictionary of resource ARN to ACL name mappings
        """
        try:
            associations = {}
            paginator = wafv2_client.get_paginator('list_web_acls')
            
            for page in paginator.paginate(Scope='REGIONAL'):
                for acl in page.get('WebACLs', []):
                    try:
                        resources = wafv2_client.list_resources_for_web_acl(
                            WebACLArn=acl['ARN'],
                            ResourceType='APPLICATION_LOAD_BALANCER'
                        ).get('ResourceArns', [])
                        
                        for resource_arn in resources:
                            associations[resource_arn] = acl['Name']
                    except ClientError:
                        continue
                        
            return associations
            
        except ClientError:
            return {}

    def execute(self, connection: boto3.Session) -> CheckReport:
        """
        Execute the WAF ACL attachment check
        Args:
            connection: AWS session
        Returns:
            CheckReport: Check results
        """
        report = CheckReport(name=__name__)
        report.passed = True

        try:
            elbv2 = connection.client('elbv2')
            wafv2 = connection.client('wafv2')
            
            try:
                # Get all ALBs
                load_balancers = [
                    lb for lb in elbv2.describe_load_balancers().get('LoadBalancers', [])
                    if lb['Type'].upper() == 'APPLICATION'
                ]
                
                if not load_balancers:
                    report.resource_ids_status["No Application Load Balancers found"] = True
                    return report
                
                # Get WAF associations
                waf_associations = self.get_waf_associations(wafv2)
                
                # Check each ALB
                for lb in load_balancers:
                    acl_name = waf_associations.get(lb['LoadBalancerArn'])
                    is_protected = bool(acl_name)
                    
                    status_msg = (
                        f"ALB {lb['LoadBalancerName']}: "
                        f"{'Protected by WAF ACL ' + acl_name if is_protected else 'No WAF ACL attached'}"
                    )
                    report.resource_ids_status[status_msg] = is_protected
                    if not is_protected:
                        report.passed = False
                
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
