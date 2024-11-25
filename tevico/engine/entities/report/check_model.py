from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from tevico.engine.core.enums import FrameworkDimension

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

class CheckReport(BaseModel):
    passed: bool = True
    name: str
    execution_time: float = 0.0
    check_metadata: Optional[CheckMetadata] = None
    dimensions: List[FrameworkDimension] = []
    framework: Optional[str] = None
    section: Optional[str] = None
    resource_ids_status: Dict[str, bool] = {}
    report_metadata: Optional[Dict[str, Any]] = None
    created_on: datetime = datetime.now()
