
from tevico.engine.configs.config import ConfigUtils
from tevico.engine.core.enums import CommandsEnum
from tevico.engine.handler import FrameworkHandler


def parse_args() -> None:
    config_utils = ConfigUtils()
    
    parser = config_utils.get_parser()
    
    args = parser.parse_args()
    
    tevico_config = config_utils.get_config_from_args(args)
    
    framework = FrameworkHandler(config=tevico_config)
    
    if args.command == CommandsEnum.run.value:
        return framework.handle_run()
    elif args.command == CommandsEnum.create.value:
        return framework.handle_create()
    
    return framework.handle_run()

