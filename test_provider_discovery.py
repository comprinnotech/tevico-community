#!/usr/bin/env python3
"""
Test script to verify provider discovery mechanism
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tevico.engine.framework import TevicoFramework

def test_provider_discovery():
    """Test that both AWS and Azure providers are discovered"""
    print("Testing Provider Discovery...")
    
    try:
        framework = TevicoFramework()
        
        # Test provider discovery by trying to get each provider
        providers_to_test = ['aws', 'azure']
        discovered_providers = []
        
        for provider_name in providers_to_test:
            try:
                provider = framework._TevicoFramework__get_provider(provider_name)
                discovered_providers.append(provider.name)
                print(f"✅ {provider.name} provider discovered successfully")
                print(f"   - Provider path: {provider.provider_path}")
                print(f"   - Account ID: {provider.account_id}")
                
            except Exception as e:
                print(f"❌ Failed to discover {provider_name} provider: {str(e)}")
        
        print(f"\n📋 Summary:")
        print(f"   - Providers discovered: {', '.join(discovered_providers)}")
        print(f"   - Total providers: {len(discovered_providers)}")
        
        if len(discovered_providers) >= 2:
            print("✅ Multi-cloud provider discovery working correctly!")
            return True
        else:
            print("⚠️  Expected at least 2 providers (AWS and Azure)")
            return False
            
    except Exception as e:
        print(f"❌ Provider discovery test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_provider_discovery()
    sys.exit(0 if success else 1)
