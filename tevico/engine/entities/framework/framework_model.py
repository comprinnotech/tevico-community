
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

from tevico.engine.entities.check.check import Check


class FrameworkSection(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: str
    description: str
    checks: Optional[List[Check]] = []
    sections: Optional[List['FrameworkSection']] = []

class FrameworkModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    name: str
    version: str
    description: str
    sections: List[FrameworkSection]
