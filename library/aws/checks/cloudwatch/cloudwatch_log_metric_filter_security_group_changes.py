"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_security_group_changes(Check):
     
    def _get_log_groups(self, logs_client):
        
        # Retrieve all log groups from CloudWatch Logs
        try:
            response = logs_client.describe_log_groups()
            return response.get('logGroups', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _get_metric_filters(self, logs_client):
        
        # Retrieve all metric filters from CloudWatch Logs
        try:
            response = logs_client.describe_metric_filters()
            return response.get('metricFilters', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def execute(self, connection: boto3.Session) -> CheckReport:
        
        # Initialize a new report with the current check's name
        report = CheckReport(name=__name__)
        report.passed = True  # Initially set to True
        
        try:
            logs_client = connection.client('logs')
            
            # Get log groups and metric filters
            log_groups = self._get_log_groups(logs_client)
            metric_filters = self._get_metric_filters(logs_client)
            
            if not log_groups:
                
                # Handle case when no log groups are found
                report.passed = False
                report.resource_ids_status['NO_LOG_GROUPS_FOUND'] = False
                return report
                
            if not metric_filters:
                
                # Handle case when no metric filters are found
                report.passed = False
                report.resource_ids_status['NO_METRIC_FILTERS_FOUND'] = False
                return report

            # Check each log group
            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName')
                if not log_group_name:
                    continue

                filter_found = False
                
                # Check metric filters for this log group
                for metric_filter in metric_filters:
                    if metric_filter.get('logGroupName') != log_group_name:
                        continue
                        
                    filter_pattern = metric_filter.get('filterPattern', '')
                    if 'security group' in filter_pattern.lower():
                        filter_found = True
                        report.resource_ids_status[log_group_name] = True
                        break
                
                # If no filter found for this log group, mark as failed
                if not filter_found:
                    report.passed = False
                    report.resource_ids_status[log_group_name] = False

        except (ClientError, BotoCoreError) as e:
            
            # Handle specific AWS client-related exceptions
            report.passed = False
            report.resource_ids_status['ERROR'] = False
            
        except Exception as e:
            
            # Handle general exceptions
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        # Return the final report
        return report
