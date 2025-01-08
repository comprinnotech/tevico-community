from enum import Enum

class CommandsEnum(str, Enum):
    run = 'run'
    create = 'create'
    
class EntitiesEnum(str, Enum):
    framework = 'framework'
    provider = 'provider'
    profile = 'profile'
    check = 'check'
    
class FrameworkDimension(str, Enum):
    cost = 'cost'
    operations = 'operations'
    performance = 'performance'
    reliability = 'reliability'
    security = 'security'
    sustainability = 'sustainability'

class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"