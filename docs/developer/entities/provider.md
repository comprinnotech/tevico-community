# Provider

The [Provider](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/provider/provider.py#L15) class represents a ***Cloud Service Provider***. 

## Location

A provider should be located in the `library/` directory and follow the structure shown below:

```
library/<PROVIDER>/
    ├── provider.py           # Main provider class that extends the Provider base class
    ├── frameworks/           # Contains framework YAML files
    ├── profiles/             # Contains profile configuration files
    └── checks/               # Directory containing all check implementations
            └── <SERVICE>/        # Subdirectories organized by service
```

## Connection

Every provider must implement the abstract `connect()` method, which establishes a connection with the cloud provider's API or SDK. This method should return a connection object that will be used by checks when they are executed.

The connection object is accessible via the `connection` property, which automatically calls the `connect()` method. The `is_connected` property can be used to verify if the connection was established successfully.

## Create New Provider

Let us assume there exists a Cloud Provider called `tvc`. To create a new provider, you need to:

1. Create a new directory - `library/tvc`
2. Create a new class called `provider.py` that inherits from the `Provider` abstract base class inside the newly created directory.
3. Implement the required abstract methods and properties:
     - `name` property: Returns the name of the provider
     - `metadata` property: Returns provider-specific metadata as a dictionary
     - `connect()` method: Establishes a connection with the cloud provider

Example of minimal implementation:

```python
from tevico.engine.entities.provider.provider import Provider

class TvcProvider(Provider):
        __provider_name: str = 'TevicoCloud'
        
        def __init__(self) -> None:
                super().__init__(os.path.dirname(__file__))
        
        def connect(self) -> Any:
                # Implement provider-specific connection logic
                return connection_object
        
        @property
        def name(self) -> str:
                return self.__provider_name
        
        @property
        def metadata(self) -> Dict[str, str]:
                return {}
```

!!! note "Using the `create` method."
    The implementation to create a new provider using the `create` method is pending. Once this is done the process can be automated.

## Best Practices

1. **Connection Management** - Implement proper error handling in the `connect()` method to gracefully handle authentication issues
2. **Configurability** - Allow customization of the provider through the config system
3. **Resource Cleanup** - Ensure proper cleanup of resources after execution
4. **Naming Convention** - Use clear and consistent naming for the provider class and its methods
5. **Documentation** - Document provider-specific requirements and setup steps

## Example

Here's an example of the [`AWS Provider`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/library/aws/provider.py#L9) implementation:

```python
import os
import boto3

from typing import Any, Dict
from tevico.engine.configs.config import ConfigUtils
from tevico.engine.entities.provider.provider import Provider

class AWSProvider(Provider):
        
        __provider_name: str = 'AWS'
        
        def __init__(self) -> None:
                super().__init__(os.path.dirname(__file__))
        
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
```

The provider class handles loading frameworks, executing checks, and collecting check reports. The base `Provider` class implements methods for traversing framework sections and executing checks in parallel using thread pools.