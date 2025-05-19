

from tevico.engine.configs.config import TevicoConfig
from tevico.engine.framework import TevicoFramework


class FrameworkHandler():
    
    framework: TevicoFramework
    config: TevicoConfig
    
    def __init__(self, config: TevicoConfig) -> None:
        self.framework = TevicoFramework()
        self.config = config

    def handle_run(self) -> None:
        self.framework.run()

    def handle_create(self) -> None:
        if not self.config.create_params:
            raise ValueError('Create config is required')
        
        self.framework.create(config=self.config.create_params)

