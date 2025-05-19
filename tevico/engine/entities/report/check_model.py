from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tevico.engine.core.enums import FrameworkDimension
from enum import Enum

######################################################################

class RemediationCode(BaseModel):
    """Remediation code for different platforms."""
    cli: Optional[str] = Field(default=None, alias='CLI')
    native_iac: Optional[str] = Field(default=None, alias='NativeIaC')
    other: Optional[str] = Field(default=None, alias='Other')
    terraform: Optional[str] = Field(default=None, alias='Terraform')


class RemediationRecommendation(BaseModel):
    """Recommendation for remediating the security check."""
    text: str = Field(..., alias='Text', description='Recommendation text')
    url: Optional[str] = Field(default=None, alias='Url')  # Optional URL


class Remediation(BaseModel):
    """Remediation steps for the security check."""
    code: RemediationCode = Field(..., alias='Code', description='Remediation code for different platforms')
    recommendation: RemediationRecommendation = Field(..., alias='Recommendation', description='Recommendation for remediating the security check')


class CheckMetadata(BaseModel):
    """Pydantic model representing security check metadata."""
    provider: str = Field(..., alias='Provider', description='Cloud provider (e.g., aws)')
    check_id: str = Field(..., alias='CheckID', description='Unique identifier for the check')
    check_title: str = Field(..., alias='CheckTitle', description='Title of the security check')
    check_aliases: Optional[List[str]] = Field(alias='CheckAliases', default_factory=list, description='Alternative names for the check')
    check_type: List[str] = Field(..., alias='CheckType', description='List of check types')
    service_name: str = Field(..., alias='ServiceName', description='Cloud service involved in the check')
    sub_service_name: str = Field(..., alias='SubServiceName', description='Sub-service within the cloud service')
    resource_id_template: str = Field(..., alias='ResourceIdTemplate', description='Template for resource identification')
    severity: str = Field(..., alias='Severity', description='Severity level of the check (e.g., high, medium)')
    resource_type: str = Field(..., alias='ResourceType', description='Type of resource the check applies to')
    risk: str = Field(..., alias='Risk', description='Explanation of the security risk involved')
    related_url: str = Field(alias='RelatedUrl', default='', description='URL for further information')
    remediation: Remediation = Field(..., alias='Remediation', description='Steps to mitigate the security risk')
    categories: Optional[List[str]] = Field(alias='Categories', default_factory=list, description='Categories associated with the check (e.g., forensics-ready)')
    depends_on: List[str] = Field(alias='DependsOn', default_factory=list, description='Checks this check depends on')
    related_to: List[str] = Field(alias='RelatedTo', default_factory=list, description='Related security checks')
    notes: Optional[str] = Field(alias='Notes', default=None, description='Additional notes about the check')
    
    description: str = Field(..., alias='Description', description='Detailed description of the security check')
    success_message: Optional[str] = None
    failure_message: Optional[str] = None

######################################################################

class AwsResource(BaseModel):
    arn: str = Field(..., description='Amazon Resource Name (ARN)')
    
    @field_validator('arn')
    def validate_arn(cls, v):
        # Split the ARN by colon and check if it has 6 or 7 parts
        parts = v.split(':')
        if len(parts) not in (6, 7) or parts[0] != 'arn':
            # If the ARN is not in the correct format, raise an error
            raise ValueError(f"Invalid ARN format: {v}")
        return v

    def __str__(self):
        return self.arn

    def model_dump(self, mode: str = 'json'):
        if mode == 'json':
            return self.arn
        return super().model_dump(mode=mode)

class GeneralResource(BaseModel):
    name: str = Field(..., description='Name of the resource')
    
    def __str__(self):
        return self.name
    
    def model_dump(self, mode: str = 'json'):
        if mode == 'json':
            return self.name
        return super().model_dump(mode=mode)


class CheckStatus(Enum):
    # If the check passed
    PASSED = 'passed'
    
    # If the check failed
    FAILED = 'failed'

    # If the check cannot be executed because of lack of information
    SKIPPED = 'skipped'
    
    # If there are no resources to check
    NOT_APPLICABLE = 'not_applicable'
    
    # If the AWS API call fails for unknown reasons
    UNKNOWN = 'unknown'
    
    # If the check errored out
    ERRORED = 'errored'


class CheckException(BaseModel):
    code: Optional[str] = None
    message: Optional[str] = None


class ResourceStatus(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    # The resource key represents the resource ID
    # It can take the form of an ARN or a resource name
    # We can further add support for other resource identifiers
    # for different cloud providers.
    resource: Union[AwsResource, GeneralResource]
    
    # The status of the check for this particular resource
    status: CheckStatus
    
    # The message associated with the status
    summary: Optional[str] = Field(..., description='Summary of the check status')
    
    # The error exception associated with the status
    exception: Optional[str] = None

    @field_validator('summary', mode='before')
    def validate_summary(cls, v, values):
        status = values.data.get('status')
        if status is not CheckStatus.PASSED and v is None:
            raise ValueError(f'Summary is required for statuses other than PASSED, currently status is set to {status}')
        return v

class CheckReport(BaseModel):
    status: Optional[CheckStatus] = None
    name: str
    execution_time: float = 0.0
    check_metadata: Optional[CheckMetadata] = None
    dimensions: List[FrameworkDimension] = []
    framework: Optional[str] = None
    section: Optional[str] = None
    resource_ids_status: List[ResourceStatus] = Field(default_factory=list)
    report_metadata: Optional[Dict[str, Any]] = None
    created_on: datetime = datetime.now()

    def set_report_status(self):
        failed_statuses = {CheckStatus.FAILED, CheckStatus.ERRORED, CheckStatus.UNKNOWN}

        if len(self.resource_ids_status) < 1 and self.status == None:
            self.status = CheckStatus.UNKNOWN
        elif any(resource.status in failed_statuses for resource in self.resource_ids_status):
            self.status = CheckStatus.FAILED
        else:
            self.status = CheckStatus.PASSED

