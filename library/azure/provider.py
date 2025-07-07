import os
from typing import Any, Dict
from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient

from tevico.engine.configs.config import ConfigUtils
from tevico.engine.entities.provider.provider import Provider


class AzureProvider(Provider):
    
    __provider_name: str = 'Azure'
    
    def __init__(self) -> None:
        super().__init__(os.path.dirname(__file__))
        self._credential = None
        self._subscription_id = None
    

    def connect(self) -> Any:
        """
        Establish connection to Azure using DefaultAzureCredential
        Falls back to AzureCliCredential if default fails
        """
        try:
            # Try DefaultAzureCredential first (supports multiple auth methods)
            self._credential = DefaultAzureCredential()
            
            # Test the credential by getting subscriptions
            subscription_client = SubscriptionClient(self._credential)
            subscriptions = list(subscription_client.subscriptions.list())
            
            if not subscriptions:
                raise Exception("No accessible Azure subscriptions found")
            
            # Use first subscription if not specified in config
            azure_config = ConfigUtils().get_config().azure_config
            if azure_config and 'subscription_id' in azure_config:
                self._subscription_id = azure_config['subscription_id']
            else:
                self._subscription_id = subscriptions[0].subscription_id
            
            return {
                'credential': self._credential,
                'subscription_id': self._subscription_id
            }
            
        except Exception as e:
            # Fallback to Azure CLI credential
            try:
                self._credential = AzureCliCredential()
                subscription_client = SubscriptionClient(self._credential)
                subscriptions = list(subscription_client.subscriptions.list())
                
                if subscriptions:
                    self._subscription_id = subscriptions[0].subscription_id
                    return {
                        'credential': self._credential,
                        'subscription_id': self._subscription_id
                    }
            except Exception as cli_error:
                raise Exception(f"Failed to authenticate with Azure: {str(e)}, CLI fallback: {str(cli_error)}")

    @property
    def name(self) -> str:
        return self.__provider_name

    @property
    def metadata(self) -> Dict[str, str]:
        return {
            'subscription_id': self._subscription_id or 'Unknown',
            'tenant_id': self._get_tenant_id()
        }

    @property
    def account_id(self) -> str:
        """Return Azure subscription ID as account identifier"""
        return self._subscription_id or "Unknown"

    @property
    def account_name(self) -> str:
        """Return Azure subscription name"""
        try:
            if self._credential and self._subscription_id:
                subscription_client = SubscriptionClient(self._credential)
                subscription = subscription_client.subscriptions.get(self._subscription_id)
                return subscription.display_name or "Unknown"
        except Exception as e:
            return "Unknown"
        return "Unknown"
    
    def _get_tenant_id(self) -> str:
        """Get Azure tenant ID"""
        try:
            if self._credential and self._subscription_id:
                subscription_client = SubscriptionClient(self._credential)
                subscription = subscription_client.subscriptions.get(self._subscription_id)
                return subscription.tenant_id or "Unknown"
        except Exception as e:
            return "Unknown"
        return "Unknown"
