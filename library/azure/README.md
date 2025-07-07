# Azure Provider for Tevico

This directory contains the Azure provider implementation for the Tevico auditing framework.

## Overview

The Azure provider enables Tevico to perform compliance and security checks against Azure cloud resources. It supports various Azure services and implements checks based on Azure Well-Architected Framework principles.

## Authentication

The Azure provider supports multiple authentication methods through Azure Identity:

1. **Azure CLI** - Uses `az login` credentials
2. **Managed Identity** - For Azure-hosted applications
3. **Service Principal** - Using client ID and secret
4. **Environment Variables** - Azure SDK environment variables

### Setup Authentication

#### Option 1: Azure CLI (Recommended for local development)
```bash
az login
az account set --subscription "your-subscription-id"
```

#### Option 2: Service Principal
```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
```

#### Option 3: Managed Identity
No additional setup required when running on Azure resources with managed identity enabled.

## Usage

### Basic Usage
```bash
# Run with default Azure authentication
./main run --csp=azure

# Run with specific subscription
./main run --csp=azure --azure_config=subscription_id:your-subscription-id

# Run with specific profile
./main run --csp=azure --profile=security_baseline
```

### Configuration Options

The `--azure_config` parameter accepts comma-separated key:value pairs:

- `subscription_id:your-subscription-id` - Target specific subscription
- `resource_group:your-rg-name` - Limit checks to specific resource group (if supported by check)

Example:
```bash
./main run --csp=azure --azure_config=subscription_id:12345678-1234-1234-1234-123456789012
```

## Supported Services

The Azure provider currently supports checks for:

- **Virtual Machines** - Encryption, configuration, and security settings
- **Storage Accounts** - Security configurations and access controls
- **Key Vault** - Access policies and security settings
- **SQL Database** - Encryption and security configurations
- **Resource Groups** - Tagging and organization

## Framework Support

### Azure Well-Architected Review
Implements checks based on the five pillars:
- Cost Optimization
- Security
- Reliability
- Performance Efficiency
- Operational Excellence

## Directory Structure

```
azure/
├── checks/           # Individual check implementations
│   ├── vm/          # Virtual Machine checks
│   ├── storage/     # Storage Account checks
│   └── keyvault/    # Key Vault checks
├── frameworks/      # Framework definitions (YAML)
├── profiles/        # Check profiles for different use cases
├── utils/          # Utility functions
├── models/         # Data models
├── tests/          # Unit tests
└── provider.py     # Main provider implementation
```

## Creating New Checks

### 1. Create Check Implementation
```python
# library/azure/checks/service/check_name.py
from azure.mgmt.service import ServiceManagementClient
from tevico.engine.entities.check.check import Check
from tevico.engine.entities.report.check_model import CheckReport

class service_check_name(Check):
    def execute(self, connection: dict) -> CheckReport:
        # Implementation here
        pass
```

### 2. Create Check Metadata
```yaml
# library/azure/checks/service/check_name.yaml
name: Check Name
description: Check description
service: service_name
risk: HIGH|MEDIUM|LOW
# Additional metadata
```

### 3. Add to Framework
Update the appropriate framework YAML file to include the new check.

## Required Permissions

The Azure provider requires the following minimum permissions:

- `Reader` role on the subscription or resource groups being audited
- Additional service-specific permissions for certain checks (documented in individual check metadata)

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Ensure you're logged in with `az login`
   - Verify subscription access with `az account show`

2. **Permission Errors**
   - Check that your account has Reader access to the subscription
   - Some checks may require additional permissions

3. **Subscription Not Found**
   - Verify the subscription ID is correct
   - Ensure you have access to the specified subscription

### Debug Mode
Enable debug logging by setting:
```bash
export AZURE_LOG_LEVEL=DEBUG
```

## Contributing

When adding new Azure checks:

1. Follow the existing code structure and patterns
2. Include comprehensive error handling
3. Add unit tests for new functionality
4. Update documentation and metadata
5. Test with multiple Azure configurations

## References

- [Azure Well-Architected Framework](https://docs.microsoft.com/en-us/azure/architecture/framework/)
- [Azure SDK for Python](https://docs.microsoft.com/en-us/azure/developer/python/)
- [Azure Identity Library](https://docs.microsoft.com/en-us/python/api/azure-identity/)
