"""
AUTHOR: Mohd Asif <mohd.asif@comprinno.net>
DATE: 2024-10-10
"""

import boto3
from datetime import datetime, timedelta, timezone
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class iam_rotate_access_keys_90_days(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('iam')

        try:
            
            current_time = datetime.now(timezone.utc)
            
            ninety_days_ago = current_time - timedelta(days=90)

            
            users = client.list_users()['Users']
            for user in users:
                username = user['UserName']
                
                access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
                
                for key in access_keys:
                    create_date = key['CreateDate']  
                    
                    
                    if key['Status'] == 'Active' and create_date < ninety_days_ago:
                        
                        report.resource_ids_status[username] = False
                    else:
                        
                        report.resource_ids_status[username] = True

            
            report.passed = all(status is True for status in report.resource_ids_status.values())

        except Exception as e:
            
            report.passed = False

        return report
