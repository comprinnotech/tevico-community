import boto3
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check


class dynamodb_tables_pitr_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client('dynamodb')

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status =ResourceStatus.PASSED
        report.resource_ids_status = {}

        try:
            # Pagination to get all DynamoDB tables
            tables = []
            next_token = None

            while True:
                response = client.list_tables(ExclusiveStartTableName=next_token) if next_token else client.list_tables()
                tables.extend(response.get('TableNames', []))
                next_token = response.get('LastEvaluatedTableName', None)

                if not next_token:
                    break

            # Check each table for Point-in-Time Recovery (PITR) status
            for table in tables:
                try:
                    response = client.describe_continuous_backups(TableName=table)
                    pitr_status = response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']

                    if pitr_status == 'ENABLED':
                        report.resource_ids_status[f"{table} has PITR enabled."] = True
                    else:
                        report.resource_ids_status[f"{table} has PITR disabled."] = False
                        report.status = ResourceStatus.FAILED

                except client.exceptions.TableNotFoundException:
                    report.resource_ids_status[f"{table} not found."] = False
                    report.status = ResourceStatus.FAILED

                except client.exceptions.ContinuousBackupsUnavailableException:
                    report.resource_ids_status[f"{table} has no continuous backups available."] = False
                    report.status = ResourceStatus.FAILED

                except Exception as e:
                    report.resource_ids_status[f"Error checking PITR for {table}: {str(e)}"] = False
                    report.status = ResourceStatus.FAILED

        except Exception as e:
            report.resource_ids_status["DynamoDB table listing error occurred."] = False
            report.status = ResourceStatus.FAILED

        return report
