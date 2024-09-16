
from typing import List, Optional
from pydantic import BaseModel, ConfigDict

from tevico.app.entities.check.check import Check
from tevico.app.entities.profile.profile_section_model import ProfileSection

class ProfileModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    module_path: Optional[str] = None
    name: str

    checks: Optional[List[Check]] = []
    sections: Optional[List[ProfileSection]] = []

