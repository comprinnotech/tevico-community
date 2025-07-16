
from tevico.engine.configs.config import ConfigUtils
from tevico.engine.core.enums import CommandsEnum
from tevico.engine.handler import FrameworkHandler


def parse_args() -> None:
    config_utils = ConfigUtils()
    
    parser = config_utils.get_parser()
    
    args = parser.parse_args()
    
    tevico_config = config_utils.get_config_from_args(args)
    
    handler = FrameworkHandler(config=tevico_config)

    return handler.execute_framework(command=args.command)

