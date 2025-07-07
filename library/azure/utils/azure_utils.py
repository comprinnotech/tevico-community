"""
Azure utility functions for Tevico framework
"""

from typing import Dict, List, Optional
from azure.core.exceptions import AzureError
from azure.mgmt.resource import ResourceManagementClient


class AzureUtils:
    """Utility class for common Azure operations"""
    
    @staticmethod
    def get_resource_groups(connection: dict) -> List[str]:
        """
        Get all resource groups in the subscription
        
        Args:
            connection: Azure connection dictionary with credential and subscription_id
            
        Returns:
            List of resource group names
        """
        try:
            credential = connection['credential']
            subscription_id = connection['subscription_id']
            
            resource_client = ResourceManagementClient(credential, subscription_id)
            resource_groups = resource_client.resource_groups.list()
            
            return [rg.name for rg in resource_groups]
        except AzureError as e:
            raise Exception(f"Failed to get resource groups: {str(e)}")
    
    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """
        Parse Azure resource ID into components
        
        Args:
            resource_id: Azure resource ID string
            
        Returns:
            Dictionary with resource ID components
        """
        parts = resource_id.split('/')
        
        if len(parts) < 8:
            return {}
        
        return {
            'subscription_id': parts[2],
            'resource_group': parts[4],
            'provider': parts[6],
            'resource_type': parts[7],
            'resource_name': parts[8] if len(parts) > 8 else ''
        }
    
    @staticmethod
    def get_resource_tags(resource) -> Dict[str, str]:
        """
        Get tags from an Azure resource
        
        Args:
            resource: Azure resource object
            
        Returns:
            Dictionary of resource tags
        """
        return resource.tags if hasattr(resource, 'tags') and resource.tags else {}
    
    @staticmethod
    def is_resource_encrypted(resource, encryption_property: str = 'encryption') -> bool:
        """
        Check if a resource has encryption enabled
        
        Args:
            resource: Azure resource object
            encryption_property: Property name to check for encryption
            
        Returns:
            True if encryption is enabled, False otherwise
        """
        if hasattr(resource, encryption_property):
            encryption_config = getattr(resource, encryption_property)
            if hasattr(encryption_config, 'enabled'):
                return encryption_config.enabled
        return False
