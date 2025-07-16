
# CLI Parameters

Tevico Community supports two primary commands: `run` and `create`. These are explained in detail below.

## Run Command

The `run` command executes the project and generates a report in a `report.zip` file. Some optional parameters are as follows:

### --thread-workers (optional)

Specifies the number of threads to be added to the thread pool for execution. At any given time, one thread is assigned to one check for execution.

If this argument is not set, it defaults to **5**. You can modify this configuration in the `TevicoConfig` class.

```bash title="Run the project with 20 workers"
./main run --thread_workers=20
```

### --profile (optional)

Specifies the [Profile](developer/entities/profile.md) that you would like to run on top of the [Framework](developer/entities/framework.md).

**NOTE:** This feature is still a `Work In Progress`. Please review the `profile` code you intend to execute before using this command.

```bash title="Run the project with the startup profile"
./main run --profile=startup
```

### --aws_config (optional)

The value for this parameter is a comma-separated string that holds key-value pairs separated by `:`.

```bash title="Run the project with AWS config"
./main run --aws_config=profile:comprinno
```

Here the `profile` is the AWS SSO profile that the process will use during execution.

## Create Command

The `create` command helps with creating entities for the project. You can create [Checks](developer/entities/check.md), [Profiles](developer/entities/profile.md), [Providers](developer/entities/provider.md), and [Frameworks](developer/entities/framework.md) using this command.

The structure of this command is as follows:

```bash
./main create <ENTITY> <NAME>
```

The entity can be one of the following:

* `check`
* `provider`
* `profile`
* `framework`

An example of this command is as follows:

```bash title="Create a check within AWS under the EC2 service"
./main create check network_acl_allow_ingress_any_port --options=service:ec2,some:other_config --provider=aws
```

### --options (required)

The `--options` param is a comma separated string of key-value pairs. The key-value pairs are separeted by `:`.

### --provider (required)

The `--provider` param is the name of the provider in lowercase.