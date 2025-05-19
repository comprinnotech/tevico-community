
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class ProfileModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str

    include_checks: Optional[List[str]] = None
    exclude_checks: Optional[List[str]] = None

