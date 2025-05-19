"""
AUTHOR: deepak-puri-comprinno
EMAIL: deepak.puri@comprinno.net
DATE: 2025-03-28
"""

import boto3
from tevico.engine.entities.report.check_model import AwsResource, GeneralResource, CheckReport, CheckStatus, ResourceStatus
from tevico.engine.entities.check.check import Check


class kms_cmk_rotation_enabled(Check):

    def execute(self, connection: boto3.Session) -> CheckReport:
        client = connection.client("kms")

        # Initialize the report
        report = CheckReport(name=__name__)
        report.status = CheckStatus.PASSED
        report.resource_ids_status = []

        try:
            keys = []
            next_token = None

            # Fetch all KMS keys with pagination
            while True:
                response = client.list_keys(Marker=next_token) if next_token else client.list_keys()
                keys.extend(response.get("Keys", []))
                next_token = response.get("NextMarker")
                if not next_token:
                    break  # Exit loop when no more pagestus

            if not keys:
                # No customer-managed CMKs found, mark as NOT_APPLICABLE
                report.status = CheckStatus.NOT_APPLICABLE
                report.resource_ids_status.append(
                    ResourceStatus(
                        resource=GeneralResource(name="KMS"),
                        status=CheckStatus.NOT_APPLICABLE,
                        summary="No customer-managed CMKs found."
                    )
                )
                return report

            for key in keys:
                key_id = key["KeyId"]

                # Get key metadata
                key_metadata = client.describe_key(KeyId=key_id)["KeyMetadata"]

                # Skip AWS-managed and disabled keys
                if key_metadata.get("KeyManager") != "CUSTOMER" or key_metadata.get("KeyState") != "Enabled":
                    continue  

                key_arn = key_metadata.get("Arn", key_id)

                try:
                    # Check rotation status
                    rotation_status = client.get_key_rotation_status(KeyId=key_id)
                    rotation_enabled = rotation_status.get("KeyRotationEnabled", False)

                    if rotation_enabled:
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=key_arn),
                                status=CheckStatus.PASSED,
                                summary=f"Key rotation is enabled for CMK {key_id}."
                            )
                        )
                    else:
                        report.status = CheckStatus.FAILED
                        report.resource_ids_status.append(
                            ResourceStatus(
                                resource=AwsResource(arn=key_arn),
                                status=CheckStatus.FAILED,
                                summary=f"Key rotation is not enabled for CMK {key_id}."
                            )
                        )

                except Exception as e:
                    report.status = CheckStatus.UNKNOWN
                    report.resource_ids_status.append(
                        ResourceStatus(
                            resource=AwsResource(arn=key_arn),
                            status=CheckStatus.UNKNOWN,
                            summary=f"Error retrieving rotation status for CMK {key_id}: {str(e)}",
                            exception=str(e)
                        )
                    )

        except Exception as e:
            report.status = CheckStatus.UNKNOWN
            report.resource_ids_status.append(
                ResourceStatus(
                    resource=GeneralResource(name="KMS"),
                    status=CheckStatus.UNKNOWN,
                    summary=f"Error fetching KMS keys: {str(e)}",
                    exception=str(e)
                )
            )

        return report
