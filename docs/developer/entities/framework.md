# Framework

A **Framework** in Tevico represents a structured set of best practices, standards, or compliance requirements (such as AWS Well-Architected, ISO27001, NIST, etc.) that are used to organize and group related checks. Frameworks help users assess their cloud infrastructure or applications against industry standards or organizational policies.

## Location

Frameworks are defined as YAML files and are located in the following directory structure:

```
library/<PROVIDER>/frameworks/
```

For example, the AWS Well-Architected Review framework is defined at:

```
library/aws/frameworks/well_architected_review.yaml
```

## Framework YAML Structure

A framework YAML file contains:
- `title`: Name of the framework (e.g., AWS Well Architected Review)
- `version`: Version of the framework
- `description`: Description and purpose
- `url`: (Optional) Link to the official documentation
- `sections`: List of sections, each with a name, description, and associated checks. Sections can be nested.

Example:

```yaml
title: AWS | Well Architected Review
version: 1.0.0
description: |
  Well-Architected Review is a comprehensive assessment framework developed by AWS to help organizations evaluate their
  cloud architectures against a set of best practices.
url: https://aws.amazon.com/architecture/well-architected/
sections:
  - name: Cost Optimization
    description: The Cost Optimization pillar includes the ability to avoid or eliminate unneeded cost or suboptimal resources.
    sections:
      - name: Cost-Effective Resources
        description: The Cost-Effective Resources section includes the ability to use resources efficiently.
        checks:
          - ec2_instance_managed_by_ssm
          - ec2_managed_instance_patch_compliance_status
```

## Creating a New Framework

To create a new framework, use the CLI:

```bash
./main create framework <NAME> --provider=<PROVIDER>
```

This will generate a new YAML file in the appropriate `frameworks/` directory using a template.

## Usage in Tevico

- Frameworks are used to group checks for reporting and compliance.
- The `TevicoFramework` class loads and manages frameworks, executes all checks defined within, and generates reports.
- You can customize or extend frameworks by editing the YAML files or creating new ones.

## Related Entities
- [Check](./check.md)
- [Profile](./profile.md)
- [Provider](./provider.md)
