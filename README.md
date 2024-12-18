# Tevico Overview

Tevico is an extensible open-source, Python-based auditing framework that empowers users to comprehensively check their infrastructure and apps for compliance adherence, security vulnerabilities, and custom operational checks.

## Table of Contents

- [Getting Started](#getting-started)
- [CLI Examples](#cli-examples)
    - [run](#run-run-the-project-with-given-configuration)
    - [create](#run-run-the-project-with-given-configuration)
- [Community Code of Conduct](#community-code-of-conduct)
- [License](#license)

## Getting Started

To run the project simply copy the following code and run it in your CloudShell.

```bash
curl https://raw.githubusercontent.com/comprinnotech/tevico-community/refs/heads/main/run.sh?ts=$(date +%s) | bash
```

## CLI Examples

Following CLI params will help you to get an idea about the project and its capabilitites.

### `run`: Run the project with given configuration

```bash
# To simply run the project with default config
./main run

# Adding provider and thread config if required
./main run --aws_config=profile:comprinno --thread_workers=20
```

### `create`: Create project entities with given configuration

```bash
# Structure around create command.
./main create <ENTITY> <NAME>

# Eg:
./main create check network_acl_allow_ingress_any_port --options=service:ec2,some:other_config --provider=aws
```

## Community Code of Conduct

Tevico current follows the CNCF Code of Conduct. You can get the details of the code of conduct [here](https://github.com/cncf/foundation/blob/master/code-of-conduct.md). For any violations of this code of conduct you can connect with us over an [email](mailto:community@tevi.co).

## License

Copyright 2024 Tevico

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.