# Check

A check is the ***"Smallest unit of Execution"*** within the framework. Any python class can turn into a Check if it inherits the [`Check`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/check/check.py#L10) *Abstract Base Class*. Once you inherit the [`Check`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/check/check.py#L10) class you simply need to implement the `execute` method that returns a [`CheckReport`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/report/check_model.py#L137).

## Metadata File

A check class holds a reference to its [`CheckMetadata`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/report/check_model.py#L30) that provides all required fields post its execution.

!!! note warning "Metadata and Check - File Names & Location"
    The file name for the check and the metadata except for its extension should be the same and they should exist right next to each other in the same directory.
    <br>
    <br>
    **Eg.**
    <br>
    Location - `library/<PROVIDER>/checks/`
    <br>
    Check File Name - iam_root_hardware_mfa_enabled.py
    <br>
    Metadata File Name -  iam_root_hardware_mfa_enabled.yaml
    

## Return CheckReport

Every check file should implement an `execute` function that ***returns an instance of [`CheckReport`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/entities/report/check_model.py#L137) class***. The `execute` method is called by the provider for which the check belongs to.

The [`TevicoFramework`](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/tevico/engine/framework.py#L19) class handles the collection of this `CheckReport` and generates the overall report.

## Create New Check

The Project provides an easy way to create entities like a Check. To create a new check simply use the command given below -

```bash
# Structure around create command.
./main create <ENTITY> <NAME>

# Eg:
./main create check network_acl_allow_ingress_any_port --options=service:ec2,some:other_config --provider=aws
```

The `--provider` flag in this `create` command is **mandatory**.

## Best Practices

1. Be On Point - The check should not digress from its purpose. It should be concise and on point.
2. Extensive - The check should cover every edge case possible.
3. Efficient - The check's code should be as efficient enough to scan through all resources and ideally return a response in <10s.
4. Naming Convention - The check should follow the naming convention pattern of `service_purpose.py`. Eg. `ec2_ebs_volume_encryption`

## Example

Some examples of checks are given below -

1. [ec2_ebs_volume_encryption](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/library/aws/checks/ec2/ec2_ebs_volume_encryption.py#L12)
2. [apigateway_rest_api_client_certificate_enabled](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/library/aws/checks/apigateway/apigateway_rest_api_client_certificate_enabled.py#L12)
3. [cloudwatch_log_metric_filter_root_usage](https://github.com/comprinnotech/tevico-community/blob/8af9e0596f1b010712c657d12cacdf86888bbdf3/library/aws/checks/cloudwatch/cloudwatch_log_metric_filter_root_usage.py#L15)