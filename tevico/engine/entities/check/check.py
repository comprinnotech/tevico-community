
from abc import ABC, abstractmethod
import time
from typing import Any


from tevico.engine.entities.report.check_model import CheckMetadata, CheckReport, CheckStatus


class Check(ABC):
    
    metadata: CheckMetadata
    
    def __init__(self, metadata: CheckMetadata) -> None:
        self.metadata = metadata
        super().__init__()
        
    def get_report(self, framework: str, section: str, connection: Any) -> CheckReport:
        check_start_time = time.time()
        check_report = self.execute(connection=connection)
        check_report.execution_time = time.time() - check_start_time
        check_report.check_metadata = self.metadata
        check_report.framework = framework
        check_report.section = section
        
        # print(f'id = {check_report.check_metadata.check_id}')
        
        # Set the check status based on resource_ids_status
        check_report.set_report_status()

        return check_report
    
    @abstractmethod
    def execute(self, connection: Any) -> CheckReport:
        raise NotImplementedError()
    
    