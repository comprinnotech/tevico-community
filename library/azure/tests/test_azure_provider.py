"""
Unit tests for Azure Provider
"""

import pytest
from unittest.mock import Mock, patch
from library.azure.provider import AzureProvider


class TestAzureProvider:
    
    def setup_method(self):
        """Setup test fixtures"""
        self.provider = AzureProvider()
    
    def test_provider_name(self):
        """Test provider name property"""
        assert self.provider.name == "Azure"
    
    @patch('library.azure.provider.DefaultAzureCredential')
    @patch('library.azure.provider.SubscriptionClient')
    def test_connect_success(self, mock_subscription_client, mock_credential):
        """Test successful Azure connection"""
        # Mock credential
        mock_cred = Mock()
        mock_credential.return_value = mock_cred
        
        # Mock subscription client and subscriptions
        mock_sub_client = Mock()
        mock_subscription_client.return_value = mock_sub_client
        
        mock_subscription = Mock()
        mock_subscription.subscription_id = "test-subscription-id"
        mock_sub_client.subscriptions.list.return_value = [mock_subscription]
        
        # Test connection
        connection = self.provider.connect()
        
        assert connection is not None
        assert 'credential' in connection
        assert 'subscription_id' in connection
        assert connection['subscription_id'] == "test-subscription-id"
    
    @patch('library.azure.provider.DefaultAzureCredential')
    @patch('library.azure.provider.SubscriptionClient')
    def test_connect_no_subscriptions(self, mock_subscription_client, mock_credential):
        """Test connection with no accessible subscriptions"""
        # Mock credential
        mock_cred = Mock()
        mock_credential.return_value = mock_cred
        
        # Mock subscription client with no subscriptions
        mock_sub_client = Mock()
        mock_subscription_client.return_value = mock_sub_client
        mock_sub_client.subscriptions.list.return_value = []
        
        # Test connection should raise exception
        with pytest.raises(Exception, match="No accessible Azure subscriptions found"):
            self.provider.connect()
    
    def test_metadata_property(self):
        """Test metadata property"""
        metadata = self.provider.metadata
        assert isinstance(metadata, dict)
        assert 'subscription_id' in metadata
        assert 'tenant_id' in metadata
    
    def test_account_id_unknown_when_not_connected(self):
        """Test account_id returns Unknown when not connected"""
        assert self.provider.account_id == "Unknown"
    
    def test_account_name_unknown_when_not_connected(self):
        """Test account_name returns Unknown when not connected"""
        assert self.provider.account_name == "Unknown"
