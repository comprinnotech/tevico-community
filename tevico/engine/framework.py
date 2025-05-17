import os
import subprocess
import time
import traceback
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader
import yaml
from tevico.engine.configs.config import CreateParams
from tevico.engine.core.enums import EntitiesEnum
from tevico.engine.core.utils import CoreUtils
from tevico.engine.entities.provider.provider import Provider
from tevico.engine.entities.provider.provider_model import ProviderMetadata
from tevico.engine.entities.report.check_model import CheckReport
from datetime import datetime

from tevico.engine.entities.report.utils import generate_analytics

class TevicoFramework():
    
    core_utils: CoreUtils = CoreUtils()
    
    def __init__(self) -> None:
        super().__init__()
    
    
    def __get_provider_metadata(self) -> List[ProviderMetadata]:
        """
        Retrieves the provider metadata for all providers.
        Returns:
            List[ProviderMetadata]: A list of ProviderMetadata objects containing the package name and class name for each provider.
        """

        provider_metatdata: List[ProviderMetadata] = []
        
        provider_list: List[str] = os.listdir('./library')
        
        for provider in provider_list:
            try:
                module_provider_path = f'./library/{provider}'
                
                if provider.startswith('_') or provider.startswith('.'):
                    continue
                
                module_provider_abspath = os.path.abspath(os.path.join(f'{module_provider_path}', f'provider.py'))    

                package_name = self.core_utils.get_package_name(module_provider_abspath)
                class_name = self.core_utils.get_class_name(module_provider_abspath)
                
                provider_metatdata.append(ProviderMetadata(package_name=package_name, class_name=class_name))
                
            except Exception as e:
                # print(f'\n 🚨 Warning: {e}')
                pass
        
        return provider_metatdata
        
    
    def __get_provider(self, name) -> Provider:
        """
        Retrieves a Provider object based on the provider metadata.
        Args:
            name (str): The name of the provider to retrieve.
        Returns:
            Provider: The matching Provider object.
        Raises:
            Exception: If no provider with the specified name is found.
        """
        
        providers: List[Provider] = []
        
        provider_metadata = self.__get_provider_metadata()
    
        for p in provider_metadata:
            provider = self.core_utils.get_provider_class(package_name=p.package_name, class_name=p.class_name)
            if provider is not None:
                providers.append(provider())

        for provider_instance in providers:
            print(f'Provider: {provider_instance.name}')
            if provider_instance.name.lower() == name:
                return provider_instance

        raise Exception(f'Provider with name {name} not found.')
    
    
    def __create_check(self, provider: str, name: str, config: Union[Dict[str, str], None]) -> None:
        """
        Creates a new check for the specified provider.
        Args:
            provider (str): The provider to use for creating the check.
            check (str): The check to create.
        Returns:
            None
        Raises:
            Exception: If an error occurs during the check creation process.
        """
        provider_checks_dir = f'./library/{provider}/checks'
        
        if not os.path.exists(provider_checks_dir):
            raise Exception(f'Provider checks directory does not exist: {provider_checks_dir}')
        
        check_dir = f'{provider_checks_dir}'
        file_prefix = ''
        
        if config is not None and 'service' in config:
            service_name = config['service']
            os.makedirs(f'{provider_checks_dir}/{service_name}', exist_ok=True)
            check_dir = f'{provider_checks_dir}/{service_name}'
            if not name.startswith(service_name):
                file_prefix = f'{service_name}_'
        
        check_file_path = f'{check_dir}/{file_prefix}{name}.py'
        metadata_file_path = f'{check_dir}/{file_prefix}{name}.yaml'
        
        j2_env = Environment(loader=FileSystemLoader('./tevico/templates'), trim_blocks=True)
        
        metadata_template = j2_env.get_template('check_metadata.jinja2')
        check_template = j2_env.get_template('check_python.jinja2')
        
        with open(metadata_file_path, 'w') as file:
            file.write(metadata_template.render(check_id=name, provider=provider))
            
        with open(check_file_path, 'w') as file:
            current_date = datetime.now().strftime('%Y-%m-%d')
            git_user_email = os.popen('git config user.email').read().strip()
            git_user_name = os.popen('git config user.name').read().strip()
            
            file.write(check_template.render(
                check_id=name,
                author=git_user_name,
                email=git_user_email,
                date=current_date,
            ))
            
        print(f'\n✅ Check created successfully: {check_file_path}')
        

    def __create_framework(self, provider: str, name: str, config: Union[Dict[str, str], None]) -> None:
        """
        Creates a new framework for the specified provider.
        Args:
            provider (str): The provider to use for creating the framework.
        Returns:
            None
        Raises:
            Exception: If an error occurs during the framework creation process.
        """
        provider_framework_dir = f'./library/{provider}/frameworks'
        
        if not os.path.exists(provider_framework_dir):
            raise Exception(f'Provider framework directory does not exist: {provider_framework_dir}')
        
        j2_env = Environment(loader=FileSystemLoader('./tevico/templates'), trim_blocks=True)
        
        framework_template = j2_env.get_template('framework_metadata.jinja2')
        framework_file_path = f'{provider_framework_dir}/{name}.yaml'
        
        with open(framework_file_path, 'w') as file:
            if config is not None:
                file.write(framework_template.render(**{str(k): v for k, v in config.items()}))
            else:
                file.write(framework_template.render())
            
        print(f'\n✅ Framework created successfully: {framework_file_path}')


    def __create_profile(self, provider: str, name: str, config: Union[Dict[str, str], None]) -> None:
        """
        Creates a new profile for the specified provider.
        Args:
            provider (str): The provider to use for creating the profile.
        Returns:
            None
        Raises:
            Exception: If an error occurs during the profile creation process.
        """
        provider_profile_dir = f'./library/{provider}/profiles'
        
        if not os.path.exists(provider_profile_dir):
            raise Exception(f'Provider profile directory does not exist: {provider_profile_dir}')
        
        j2_env = Environment(loader=FileSystemLoader('./tevico/templates'), trim_blocks=True)
        
        profile_template = j2_env.get_template('profile_metadata.jinja2')
        profile_file_path = f'{provider_profile_dir}/{name}.yaml'
        
        with open(profile_file_path, 'w') as file:
            if config is not None:
                file.write(profile_template.render(**{str(k): v for k, v in config.items()}))
            else:
                file.write(profile_template.render())
            
        print(f'\n✅ Profile created successfully: {profile_file_path}')
    

    def __create_provider(self) -> None:
        raise NotImplementedError('Provider create not implemented.')
    
    def create(self, config: CreateParams) -> None:
        """
        Creates a new entity for the specified provider.
        Args:
            entity (str): The entity type to create.
            name (str): The name of the entity to create.
            provider (str): The provider to use for creating the entity.
        Returns:
            None
        Raises:
            Exception: If an error occurs during the entity creation process.
        """
        
        
        if config.entity == EntitiesEnum.provider.value:
            return self.__create_provider()
        elif config.entity == EntitiesEnum.profile.value:
            return self.__create_profile(provider=config.provider, name=config.name, config=config.options)
        elif config.entity == EntitiesEnum.check.value:
            return self.__create_check(provider=config.provider, name=config.name, config=config.options)
        elif config.entity == EntitiesEnum.framework.value:
            return self.__create_framework(provider=config.provider, name=config.name, config=config.options)
        else:
            raise Exception('Invalid entity type.')
        
        
    def __build_report(self) -> None:
        
        build_dir = './tevico/report'
        dist_folder = 'dist'
        dist_path = f'{build_dir}/{dist_folder}'
        zip_file_path = './report.zip'
        
        if os.path.exists(dist_path):
            subprocess.run(['rm', '-rf', dist_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # report_process = subprocess.Popen(['npm', 'run', 'build'], cwd=build_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # _, stderr = report_process.communicate()
        
        # if report_process.returncode != 0:
            # print(f'\n❌ Error building report: {stderr}')
            # os._exit(1)

        current_dir = os.getcwd()

        try:
            os.chdir('./tevico/report')
            
            subprocess.run(['zip', '-r', '../../report.zip', '.'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        finally:
            os.chdir(current_dir)
        
        if not os.path.exists(zip_file_path):
            print(f'\n❌ Error creating zip file: {zip_file_path}')
            os._exit(1)

        print(f'📦 Report zipped successfully: {os.path.abspath(zip_file_path)}')
    
    def __get_war_structure(self, provider: str) -> Optional[Dict[str, Any]]:
        war_raw_path = f'./library/{provider}/frameworks/well_architected_review.yaml'
        
        if not os.path.exists(war_raw_path):
            print(f'\n❌ WAR structure file does not exist: {war_raw_path}')
            return None
        
        with open(war_raw_path, 'r') as file:
            war_structure = yaml.safe_load(file)
        
        return war_structure
    
    def run(self):
        """
        Executes the checks for all providers and generates a report.
        Returns:
            None
        Raises:
            Exception: If an error occurs during the check execution process.
        """
        
        print('\n🚀 Starting Tevico Framework Execution\n')

        start_time = time.time()
        print(self.core_utils.get_tevico_config().csp)
        provider = self.__get_provider(self.core_utils.get_tevico_config().csp)
        checks: List[CheckReport] = []
        
        try:
            print(f'\n* Running checks for provider 🚀: {provider.name}')
            provider.connect()
            result = provider.start_execution()
            checks.extend(result)
        except Exception as e:
            print(f'\n❌ Error: {e}')
            print(traceback.format_exc())
            os._exit(1)
        
        data = [s.model_dump(mode='json') for s in checks]
        
        j2_env = Environment(loader=FileSystemLoader('./tevico/templates'), trim_blocks=True)
        
        check_data_template = j2_env.get_template('check_data.jinja2')
        
        data_file_path = f'./tevico/report/data/check_report.js'
        
        analytics_report = generate_analytics(checks)
        
        with open(data_file_path, 'w') as file:
            file.write(check_data_template.render(
                check_reports=data,
                check_analytics=analytics_report.model_dump(),
                war_report=self.__get_war_structure('aws'),
                account_id=provider.account_id,
                account_name=provider.account_name,
            ))
        
        print('\nReport Overview:')
        print(f'#️⃣   Total          : {analytics_report.check_status.total}\n')
        
        print('Out of which:')
        print(f'✅  Passed         : {analytics_report.check_status.passed}')
        print(f'❌  Failed         : {analytics_report.check_status.failed}')
        print(f'⏩  Skipped        : {analytics_report.check_status.skipped}')
        print(f'⚠️  Not Applicable : {analytics_report.check_status.not_applicable}')
        print(f'❓  Unknown        : {analytics_report.check_status.unknown}')
        print(f'🛑  Errored        : {analytics_report.check_status.errored}')
        
        print('\n🛠️  Building zipped package')
        
        self.__build_report()
        
        print(f'\n🕒 Execution Time: {round(time.time() - start_time, 2)} seconds')
        print('\n👋👋👋 Bye!')
