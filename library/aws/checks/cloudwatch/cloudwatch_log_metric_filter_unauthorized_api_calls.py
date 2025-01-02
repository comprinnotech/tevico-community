"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check

class cloudwatch_log_metric_filter_unauthorized_api_calls(Check):
      
    def _get_log_groups(self, client):
        """Get all CloudWatch log groups"""
        try:
            response = client.describe_log_groups()
            return response.get('logGroups', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _get_metric_filters(self, client, log_group_name):
        """Get metric filters for a specific log group"""
        try:
            response = client.describe_metric_filters(logGroupName=log_group_name)
            return response.get('metricFilters', [])
        except (ClientError, BotoCoreError, Exception):
            return []

    def _has_unauthorized_api_filter(self, filters):
        """Check if any filter matches unauthorized API calls pattern"""
        required_terms = ['UnauthorizedOperation', 'AccessDenied']
        
        for filter_obj in filters:
            filter_pattern = filter_obj.get('filterPattern', '').lower()
            if all(term.lower() in filter_pattern for term in required_terms):
                return True
        return False

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)
        report.passed = True
        
        try:
            client = connection.client('logs')
            
            # Get log groups
            log_groups = self._get_log_groups(client)
            
            if not log_groups:
                report.passed = False
                report.resource_ids_status['NO_LOG_GROUPS_FOUND'] = False
                return report

            # Check each log group for required filter
            for log_group in log_groups:
                log_group_name = log_group.get('logGroupName')
                if not log_group_name:
                    continue

                # Get metric filters for this log group
                filters = self._get_metric_filters(client, log_group_name)
                
                if not filters:
                    report.passed = False
                    report.resource_ids_status[log_group_name] = False
                    continue

                # Check if required filter exists
                has_required_filter = self._has_unauthorized_api_filter(filters)
                
                report.resource_ids_status[log_group_name] = has_required_filter
                
                # If any log group doesn't have the required filter, the entire check fails
                if not has_required_filter:
                    report.passed = False

        except (ClientError, BotoCoreError):
            report.passed = False
            report.resource_ids_status['ERROR'] = False
        except Exception:
            report.passed = False
            report.resource_ids_status['ERROR'] = False

        return report
