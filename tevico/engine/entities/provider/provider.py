from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor
import os
from typing import Any, Dict, List, Optional

import yaml

from tevico.engine.configs.config import ConfigUtils, TevicoConfig
from tevico.engine.core.utils import CoreUtils
from tevico.engine.entities.framework.framework_model import FrameworkModel, FrameworkSection
from tevico.engine.entities.profile.profile_model import ProfileModel
from tevico.engine.entities.report.check_model import CheckReport, ResourceStatus
from tevico.engine.entities.check.check import Check

class Provider(ABC):
    
    provider_path: str
    utils: CoreUtils = CoreUtils()
    config: TevicoConfig = ConfigUtils().get_config()
    
    def __init__(self, path) -> None:
        self.provider_path = path
        super().__init__()
        
    """
    Already Implemented Properties
    """
    @property
    def frameworks(self) -> List[FrameworkModel]:
        return self.load_frameworks()
    
    @property
    def connection(self) -> Any:
        return self.connect()
    
    
    """
    Abstract Properties
    """
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()
    
    @property
    @abstractmethod
    def metadata(self) -> Dict[str, str]:
        return {}

    @property
    def is_connected(self) -> bool:
        return self.connection is not None


    """
    Abstract methods
    """
    @abstractmethod
    def connect(self) -> Any:
        raise NotImplementedError()
    
    def handle_check_execution(self, check: Check, section: str, framework: str) -> CheckReport:
        res = check.get_report(framework=framework, section=section, connection=self.connection)
        
        res.execution_time = round(res.execution_time, 2)

        if res is not None and res.status is ResourceStatus.PASSED:
            print(f'\t\t* Check Passed ✅: {res.name} ({res.execution_time} seconds)')
        elif res is not None and res.status is ResourceStatus.FAILED:
            print(f'\t\t* Check Failed ❌: {res.name} ({res.execution_time} seconds)')
        elif res is not None and res.status is ResourceStatus.SKIPPED:
            print(f'\t\t* Check Skipped ⏩: {res.name} ({res.execution_time} seconds)')
        elif res is not None and res.status is ResourceStatus.NOT_APPLICABLE:
            print(f'\t\t* Check Not Applicable ⚠️: {res.name} ({res.execution_time} seconds)')
        elif res is not None and res.status is ResourceStatus.UNKNOWN:
            print(f'\t\t* Check Unknown ❓: {res.name} ({res.execution_time} seconds)')
        else:
            print(f'\t\t* Check Unknown ❓: {res.name} ({res.execution_time} seconds)')
        
        return res
    
    def execute_checks_in_section(
        self,
        section: FrameworkSection,
        thread_pool: ThreadPoolExecutor,
        framework: FrameworkModel
    ) -> List[Future[CheckReport]]:
        
        result: List[Future[CheckReport]] = []
        
        if section.checks is not None:
            for check in section.checks:
                res = thread_pool.submit(self.handle_check_execution, check, section.name, framework.name)
                result.append(res)
        
        if section.sections is not None:
            for sub_section in section.sections:
                result.extend(self.execute_checks_in_section(sub_section, thread_pool, framework))
        
        return result

    def start_execution(self) -> List[CheckReport]:
        thread_pool = ThreadPoolExecutor(max_workers=self.config.thread_workers)
        check_reports: List[CheckReport] = []
        futures: List[Future[CheckReport]] = []

        for framework in self.frameworks:
            print(f'\t* Load Framework ✅: {framework.name}')
            
            if framework.sections is not None:
                for section in framework.sections:
                    res = self.execute_checks_in_section(section, thread_pool, framework)
                    futures.extend(res)
            
            check_reports = [f.result() for f in futures]
            
        return check_reports
    
    def __load_profile(self, profile_name: str) -> Optional[ProfileModel]:
        profile_metadata_path = f'{self.provider_path}/profiles/{profile_name}.yaml'
        
        if not os.path.exists(profile_metadata_path):
            return None
        
        with open(profile_metadata_path, 'r') as f:
            profile_raw_data = yaml.safe_load(f)
            return ProfileModel(**profile_raw_data)
    
    def __is_check_included(self, check_name: str) -> bool:
        if self.config.profile is None:
            return True
        
        profile = self.__load_profile(self.config.profile)
        
        if profile is None:
            return True
        
        if profile.exclude_checks is None and profile.include_checks is None:
            return True
        
        if profile.exclude_checks is not None and check_name not in profile.exclude_checks:
            return True
        
        if profile.include_checks is not None and check_name in profile.include_checks:
            return True
        
        return False

    def __load_section(self, raw_section_data: Dict[str, Any]) -> FrameworkSection:
        if 'checks' in raw_section_data and isinstance(raw_section_data['checks'], list):
            check_list = raw_section_data['checks']
            checks: List[Check] = []
            for check_name in check_list:
                
                if not self.__is_check_included(check_name):
                    continue
                
                # check = self.__load_check(check_name=check_name)
                check = self.utils.load_check(
                    check_name=check_name,
                    provider_path=self.provider_path
                )
                if check is not None:
                    checks.append(check)
            
            raw_section_data['checks'] = checks
        
        if 'sections' in raw_section_data and isinstance(raw_section_data['sections'], list):
            section_list = raw_section_data['sections']
            sections: List[FrameworkSection] = []

            for section in section_list:
                sections.append(self.__load_section(section))
            
            raw_section_data['sections'] = sections
        
        return FrameworkSection(**raw_section_data)


    def __load_framework(self, raw_framework_data: Dict[str, Any]) -> Optional[FrameworkModel]:
        
        if 'sections' not in raw_framework_data or not isinstance(raw_framework_data['sections'], list):
            return None
        
        section_list = raw_framework_data['sections']
        sections: List[FrameworkSection] = []
        
        for section in section_list:
            sections.append(self.__load_section(section))
        
        raw_framework_data['sections'] = sections
        
        return FrameworkModel(**raw_framework_data)


    def load_frameworks(self) -> List[FrameworkModel]:
        frameworks: List[FrameworkModel] = []
        
        framework_metadata_directory: str = f'{self.provider_path}/frameworks'
        
        if not self.is_connected:
            raise Exception(f'Provider ({self.name}) is not connected')
        
        for file in os.listdir(framework_metadata_directory):
            if file.startswith('_') or file.startswith('.'):
                continue
            
            framework_metadata_path = os.path.join(framework_metadata_directory, file)
            
            framework_raw_data = None
            
            with open(os.path.join(framework_metadata_path), 'r') as f_metadata:
                framework_raw_data = yaml.safe_load(f_metadata)
                
            if framework_raw_data is None:
                continue
            
            framework_metadata = self.__load_framework(framework_raw_data)
            
            if framework_metadata is not None:
                frameworks.append(framework_metadata)

        return frameworks
