import boto3

from tevico.engine.entities.report.check_model import CheckReport
from tevico.engine.entities.check.check import Check


class dynamodb_tables_pitr_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('dynamodb')
        response = client.list_tables()
        tables = response['TableNames']

        report = CheckReport(name=__name__)

        for table in tables:
            response = client.describe_continuous_backups(TableName=table)
            report.status = response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED'
            report.resource_ids_status[table] = report.status

        return report
