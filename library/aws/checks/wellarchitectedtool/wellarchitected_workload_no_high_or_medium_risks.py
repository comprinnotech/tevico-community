"""
AUTHOR: SUPRIYO BHAKAT
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-13
"""

import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class wellarchitected_workload_no_high_or_medium_risks(Check):
    
    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        client = connection.client('wellarchitected')
        
        workloads = client.list_workloads()
        
        for workload in workloads['WorkloadSummaries']:
            workload_id = workload['WorkloadId']
            workload_name = workload['WorkloadName']
            
            workload_details = client.get_workload(WorkloadId=workload_id)
            
            high_risk_count = 0
            medium_risk_count = 0

            lenses = workload_details.get('Lenses', [])
            for lens in lenses:
                pillars = lens.get('Pillars', [])
                for pillar in pillars:
                    questions = pillar.get('Questions', [])
                    for question in questions:
                        if question.get('Risk') == 'HIGH':
                            high_risk_count += 1
                        elif question.get('Risk') == 'MEDIUM':
                            medium_risk_count += 1
                        
                      
                        if high_risk_count > 0 or medium_risk_count > 0:
                            break
                    if high_risk_count > 0 or medium_risk_count > 0:
                        break
                if high_risk_count > 0 or medium_risk_count > 0:
                    break

            report.status = high_risk_count == 0 and medium_risk_count == 0
            report.resource_ids_status[workload_id] = report.status

        return report



