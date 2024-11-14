"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-14
"""

import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import ClientError

class lambda_function_not_publicly_accessible(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('lambda')
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            functions = client.list_functions()['Functions']
            
            for function in functions:
                function_name = function['FunctionName']
                try:
                    policy = client.get_policy(FunctionName=function_name)
                    policy_json = policy['Policy']
                    
                    if '"Effect": "Allow"' in policy_json and '"Principal": "*"' in policy_json:
                        report.resource_ids_status[function_name] = False
                        report.passed = False
                    else:
                        report.resource_ids_status[function_name] = True
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceNotFoundException':
                        report.resource_ids_status[function_name] = True
                    else:
                        report.resource_ids_status[function_name] = False
                        report.passed = False
                        
        except ClientError as e:
            report.passed = False

        return report

