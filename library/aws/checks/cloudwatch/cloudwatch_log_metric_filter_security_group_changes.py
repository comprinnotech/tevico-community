"""
AUTHOR: Supriyo Bhakat
EMAIL: supriyo.bhakat@comprinno.net
DATE: 2024-11-15
"""
import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class cloudwatch_log_metric_filter_security_group_changes(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        report = CheckReport(name=__name__)

        logs_client = connection.client('logs')

        try:
            log_groups = logs_client.describe_log_groups()
            metric_filters = logs_client.describe_metric_filters()

            filter_found = False
            for log_group in log_groups['logGroups']:
                for filter in metric_filters['metricFilters']:
                    if 'root' in filter['filterPattern'] or 'security group' in filter['filterPattern']:
                        filter_found = True
                        report.passed = True
                        report.resource_ids_status[log_group['logGroupName']] = True
                        break
                if filter_found:
                    break

            if not filter_found:
                report.passed = False
                report.resource_ids_status['No relevant filters'] = False

        except logs_client.exceptions.ResourceNotFoundException:
            report.passed = False
            report.resource_ids_status['No log groups or filters found'] = False

        except Exception:
            report.passed = False
            report.resource_ids_status['Error'] = False

        return report
