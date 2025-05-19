

from typing import Any, Dict, List
from pydantic import BaseModel, field_validator

from tevico.engine.entities.profile.profile_model import ProfileModel


class ProviderModel(BaseModel):
    name: str
    profiles: List[ProfileModel] = []
    metadata: Dict[str, str] = {}
    connection: Any = None
    
    @property
    def is_connected(self) -> bool:
        return self.connection is not None
    

class ProviderMetadata(BaseModel):
    package_name: str
    class_name: str