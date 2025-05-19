import importlib
import importlib.util
import os
from typing import Optional, Type, Any

import yaml

from tevico.engine.configs.config import TevicoConfig
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckMetadata


class CoreUtils:
    
    def get_provider_class(self, package_name: str, class_name: str) -> Optional[Type[Any]]:
        """
        Retrieves the class object from the specified package and class name.
        Args:
            package_name (str): The name of the package.
            class_name (str): The name of the class.
        Returns:
            Optional[Type[Any]]: The class object if found, otherwise None.
        """
        
        module_spec = importlib.util.find_spec(package_name)
        
        if module_spec is not None:
            module_type = importlib.util.module_from_spec(module_spec)
            
            if module_spec.loader is not None:
                module_spec.loader.exec_module(module_type)
                cls = getattr(module_type, class_name)
                
                return cls
        
        return None
    
    def get_package_name(self, file_path: str) -> str:
        """
        Returns the package name based on the given file path relative to the library directory.
        Args:
            file_path (str): The path of the file.
        Returns:
            str: The package name.
        """
        
        path = file_path.split(os.path.sep)
        path = path[path.index('library'):]
        path[-1] = path[-1].replace('.py', '')
        return '.'.join(path)
    
    
    def get_class_name(self, file_path: str) -> str:
        """
        Retrieves the name of the class defined in the given file.
        Args:
            file_path (str): The path to the file.
        Returns:
            str: The name of the class defined in the file. If no class is found, an empty string is returned.
        """
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if 'class' in line:
                    return line.split(' ')[1].split('(')[0]
            return ""
    
    def get_tevico_config(self) -> TevicoConfig:
        """
        Retrieves the Tevico configuration.
        Returns:
            TevicoConfig: The Tevico configuration.
        """
        
        return TevicoConfig()
    
    def get_metadata_path(self, check_name: str, provider_path: str) -> Optional[str]:
        file_name = f'{check_name}.yaml'
        
        for root, _, files in os.walk(provider_path):
            if file_name in files:
                return os.path.join(root, file_name)

        return None
    
    def get_check_path(self, check_name: str, provider_path: str) -> Optional[str]:
        file_name = f'{check_name}.py'
        
        for root, _, files in os.walk(provider_path):
            if file_name in files:
                return os.path.join(root, file_name)
        
        return None
    
    def get_check_metadata(self, check_name: str, provider_path: str) -> Optional[CheckMetadata]:
        metadata_path = self.get_metadata_path(
            check_name=check_name,
            provider_path=provider_path
        )
        
        if metadata_path is not None:
            with open(metadata_path, 'r') as f:
                m = yaml.safe_load(f)
                return CheckMetadata(**m)
        
        return None
    
    def get_check_class(self, check_path: str, metadata: CheckMetadata) -> Optional[Check]:
        check_name = metadata.check_id
        
        module_name = self.get_package_name(check_path)
        cls = self.get_provider_class(module_name, check_name)
        
        if cls is None:
            return None
        
        return cls(metadata)
    
    def load_check(self, check_name: str, provider_path: str) -> Optional[Check]:
        
        check_path = self.get_check_path(
            check_name=check_name,
            provider_path=provider_path
        )
        
        metadata = self.get_check_metadata(check_name, provider_path)
        
        if check_path is None:
            return None
        
        if metadata is None:
            return None
        
        return self.get_check_class(check_path, metadata)
