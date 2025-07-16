# Profile

Sometimes for a given [Framework](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/framework/framework_model.py#L16) not all checks are applicable to a given organization. Let us say for example a check like [`iam_root_hardware_mfa_enabled`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/library/aws/checks/iam/iam_root_hardware_mfa_enabled.py#L11) for a startup might be an overkill but for a large corporate or for a bank it might be very well applicable. You can create different profiles to `include` and `exclude` checks.

## Location

One can create multiple `profiles` in the location `library/<PROVIDER>/profiles/`.

Eg. If you want to create a profile for a bank inside the AWS provider you can simply create a YAML file at `library/aws/profiles/startup.yaml` and the content of the file will look something like

```YAML title="startup.yaml"
name: Checks only meant for startups!
description: |
  This section checks for the presence of a Well Architected Review in the AWS account and is only meant for startups.
exclude_checks:
  - iam_root_hardware_mfa_enabled
```

## Include Checks

The `include_check` field is a list of checks that are supposed to be ***picked up*** during the execution. These should be a subset of the checks within the framework specified.

## Exclude Checks

The `include_check` field is a list of checks that are supposed to be ***excluded*** during the execution. These should be a subset of the checks within the framework specified.

## Using the profile

To use a profile during the execution you can simply use the `---profile=` CLI param.

Eg:

```bash title="Using the --profile param"
./main run --profile=startup
```

## Create new profile

To create a new profile, follow these steps:

1. Identify which provider the profile will target (e.g., AWS, Azure, GCP)
2. Create a new YAML file in the appropriate directory:
    - `library/<PROVIDER>/profiles/<PROFILE_NAME>.yaml`
3. Define the following fields in your YAML file:

```yaml
name: Your Profile Name
description: |
  A detailed description of when and why this profile should be used.
  You can include multiple lines to elaborate.
include_checks:  # Optional - list of checks to explicitly include
  - check_id_1
  - check_id_2
exclude_checks:  # Optional - list of checks to explicitly exclude
  - check_id_3
  - check_id_4
```

4. Ensure your profile has a meaningful name and a clear description
5. Test your profile using the CLI with the `--profile` parameter:

```bash
./main run --profile=<PROFILE_NAME>
```
