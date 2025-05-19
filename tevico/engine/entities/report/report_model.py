
from typing import List
from pydantic import BaseModel

class SeverityReport(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class CheckStatusReport(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    not_applicable: int = 0
    unknown: int = 0
    errored: int = 0

class GeneralReport(BaseModel):
    name: str
    check_status: CheckStatusReport
    severity: SeverityReport

class AnalyticsReport(BaseModel):
    check_status: CheckStatusReport
    severity: SeverityReport

    by_services: List[GeneralReport]
    
    by_sections: List[GeneralReport]
    
    by_severities: List[GeneralReport]
