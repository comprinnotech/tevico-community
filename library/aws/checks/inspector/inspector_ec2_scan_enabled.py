"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2024-11-12
"""
import boto3
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check
from botocore.exceptions import EndpointConnectionError, ClientError

class inspector_ec2_scan_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('inspector2')
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            # Get EC2 scanning status using list_coverage
            response = client.list_coverage(
                filterCriteria={
                    'resourceType': [{
                        'comparison': 'EQUALS',
                        'value': 'EC2_INSTANCE'
                    }]
                }
            )
            
            # If no resources found, mark as failed
            if not response.get('coveredResources'):
                report.passed = False
                return report
            
            # Check each resource's scanning status
            for resource in response.get('coveredResources', []):
                instance_id = resource.get('resourceId')
                scan_status = resource.get('scanStatus', {}).get('statusCode')
                scan_enabled = scan_status == 'ACTIVE'
                
                # Update report based on scan status
                report.resource_ids_status[instance_id] = scan_enabled
                if not scan_enabled:
                    report.passed = False
                    
        except EndpointConnectionError as e:
            report.passed = False
        except ClientError as e:
            report.passed = False
        except Exception as e:
            report.passed = False
            
        return report


