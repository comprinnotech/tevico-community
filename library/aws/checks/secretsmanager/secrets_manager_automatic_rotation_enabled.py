"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-20
"""


import boto3
from tevico.engine.entities.report.check_model import AwsResource, CheckReport, CheckStatus, GeneralResource, ResourceStatus
from tevico.engine.entities.check.check import Check


class secrets_manager_automatic_rotation_enabled(Check):
    def execute(self, connection: boto3.Session) -> CheckReport:
        # Initialize report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED  # Default to PASSED
        report.resource_ids_status = []

        try:
            client = connection.client("secretsmanager")

            # Pagination for listing all secrets
            secrets = []
            next_token = None

            while True:
                response = client.list_secrets(NextToken=next_token) if next_token else client.list_secrets()
                secrets.extend(response.get("SecretList", []))
                next_token = response.get("NextToken")

                if not next_token:
                    break

            # If no secrets exist, mark as NOT_APPLICABLE
            if not secrets:
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name=""),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No secrets found in Secrets Manager.",
                    )
                )
                return report

            # Check each secret for automatic rotation
            for secret in secrets:
                secret_arn = secret["ARN"]
                try:
                    secret_name = secret.get("Name", "Unknown Secret")
                    rotation_enabled = secret.get("RotationEnabled", False)

                    if rotation_enabled:
                        summary = f"Automatic rotation is enabled for secret: {secret_name}."
                        status = CheckStatus.PASSED
                    else:
                        summary = f"Automatic rotation is NOT enabled for secret: {secret_name}."
                        status = CheckStatus.FAILED
                        report.status = CheckStatus.FAILED  # At least one secret is non-compliant

                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=secret_arn),
                            status=status,
                            summary=summary,
                        )
                    )
                except Exception as e:
                    # Handle AWS client errors
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=secret_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving secrets from Secrets Manager: {str(e)}",
                            exception=str(e),
                        )
                    )

        except Exception as e:
            # Handle AWS client errors
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name=""),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error retrieving secrets from Secrets Manager: {str(e)}",
                    exception=str(e),
                )
            )

        return report
