"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class wellarchitected_workload_no_high_or_medium_risks(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            client = connection.client('wellarchitected')
            workloads = client.list_workloads()
            
            for workload in workloads['WorkloadSummaries']:
                workload_id = workload['WorkloadId']
                
                try:
                    # Get all answers directly using list_answers API
                    paginator = client.get_paginator('list_answers')
                    has_risks = False
                    
                    for page in paginator.paginate(
                        WorkloadId=workload_id,
                        PillarId='ALL'  # Get answers for all pillars
                    ):
                        # Check if any answer has HIGH or MEDIUM risk
                        for answer in page['AnswerSummaries']:
                            if answer.get('Risk') in ['HIGH', 'MEDIUM']:
                                has_risks = True
                                break
                        if has_risks:
                            break
                    
                    report.resource_ids_status[workload_id] = not has_risks
                    if has_risks:
                        report.passed = False

                except (ClientError, BotoCoreError):
                    report.resource_ids_status[f"{workload_id} (Error checking workload)"] = False
                    report.passed = False
                    
        except (ClientError, BotoCoreError):
            report.resource_ids_status['Error accessing Well-Architected Tool'] = False
            report.passed = False

        return report



