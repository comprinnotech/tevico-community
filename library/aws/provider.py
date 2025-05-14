import os
import boto3
from typing import Any, Dict
from tevico.engine.configs.config import ConfigUtils
from tevico.engine.entities.provider.provider import Provider
from library.aws.checks.ec2.check_ec2_detailed_monitoring import ec2_detailed_monitoring  # Import the check function

class AWSProvider(Provider):
    __provider_name: str = 'AWS'

    def __init__(self) -> None:
        super().__init__(os.path.dirname(__file__))

    def start_execution(self) -> list:
        session = self.connect()
        results = []

        # Run the EC2 detailed monitoring check
        results.append(ec2_detailed_monitoring(session))  # Add the results from the check

        return results

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

