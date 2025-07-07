
import argparse
from enum import Enum
import textwrap
from typing import Dict, Optional
from pydantic import BaseModel

from tevico.engine.core.enums import CommandsEnum


class EntitiesConfig(BaseModel):
    channels: Optional[list[str]]
    providers: Optional[list[str]]
    profiles: Optional[list[str]]
    checks: Optional[list[str]]

class ModuleLocation(str, Enum):
    local = 'local'
    home = 'home'

class EntityModuleMapping(BaseModel):
    module_name: str
    type: ModuleLocation
    entity_config: EntitiesConfig
    is_default: bool = False


class CreateParams(BaseModel):
    entity: str
    name: str
    provider: str
    options: Optional[Dict[str, str]] = None

class TevicoConfig(BaseModel):
    csp: Optional[str] = 'aws'
    profile: Optional[str] = None
    aws_config: Optional[Dict[str, str]] = None
    azure_config: Optional[Dict[str, str]] = None
    create_params: Optional[CreateParams] = None
    thread_workers: Optional[int] = 5


class ConfigUtils():
    def get_config_from_args(self, args: argparse.Namespace) -> TevicoConfig:
        config = TevicoConfig()
        
        # TODO: Identify the CSP from the environment
        if 'csp' in args and args.csp is not None:
            config.csp = args.csp

        if 'profile' in args and args.profile is not None:
            config.profile = args.profile
        
        if 'aws_config' in args and args.aws_config is not None:
            aws_config = {}

            for key_value in args.aws_config.split(','):
                key, value = key_value.split(':')
                aws_config[key] = value
            
            config.aws_config = aws_config
        
        if 'azure_config' in args and args.azure_config is not None:
            azure_config = {}

            for key_value in args.azure_config.split(','):
                key, value = key_value.split(':')
                azure_config[key] = value
            
            config.azure_config = azure_config
            
        
        if args.command == CommandsEnum.run.value:
            if 'thread_workers' in args and args.thread_workers is not None:
                config.thread_workers = args.thread_workers
            
        if args.command == CommandsEnum.create.value:
            create_params = {
                'entity': args.entity,
                'name': args.name,
                'provider': args.provider
            }
            
            create_params['options'] = {}
            
            if 'options' in args and args.options is not None:
                for key_value in args.options.split(','):
                    key, value = key_value.split(':')
                    create_params['options'][key] = value
            
            create_params = CreateParams(**create_params)
            
            config.create_params = create_params
            
        return config
    
    def get_parser(self) -> argparse.ArgumentParser:
        epilog = textwrap.dedent("""
            Additional Help:
            Visit our GitHub page for more information - https://github.com/abhaynpai/tevico
            For enterprise edition of this provider visit - https://tevi.co
        """)
        
        parser = argparse.ArgumentParser(prog='tevico', formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
        
        subparser = parser.add_subparsers(dest='command')
        
        run_parser = subparser.add_parser('run')
        run_parser.add_argument('--profile', help='The profile to run the checks against.')
        run_parser.add_argument('--aws_config', help='The AWS configuration to use for the checks.')
        run_parser.add_argument('--azure_config', help='The Azure configuration to use for the checks.')
        run_parser.add_argument('--thread_workers', help='The number of workers to use for running the checks.', type=int)

        create_parser = subparser.add_parser('create')
        create_parser.add_argument('entity', help='The entity to create.', choices=['framework', 'provider', 'profile', 'check'])
        create_parser.add_argument('name', help='The name of the entity to create.')
        create_parser.add_argument('--provider', help='The provider to create the entity for.', required=True)
        create_parser.add_argument('--options', help='The configuration options for the entity to create.', required=False)
        
        return parser
    
    def get_config(self) -> TevicoConfig:
        return self.get_config_from_args(self.get_parser().parse_args())