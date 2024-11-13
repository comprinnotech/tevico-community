import os
import boto3

from typing import Any, Dict
from framework.engine.configs.config import ConfigUtils
from framework.engine.entities.provider.provider import Provider


class AWSProvider(Provider):
    
    __provider_name: str = 'AWS'
    
    def __init__(self) -> None:
        super().__init__(os.path.dirname(__file__))
    

    def connect(self) -> Any:
        aws_config = ConfigUtils().get_config().aws_config

        if aws_config is not None:
            return boto3.Session(profile_name=aws_config['profile'])
        
        return boto3.Session()

    @property
    def name(self) -> str:
        return self.__provider_name

    @property
    def metadata(self) -> Dict[str, str]:
        return {}

