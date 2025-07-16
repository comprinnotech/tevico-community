
## Project layout

    docs/
        assets/                        # Assets required for documentation
        index.md                       # The documentation homepage.
        ...                            # Other markdown pages, images and other files.
    library/                           # -> The library that holds Checks, Frameworks and Profiles
      provider/                        # -> A provider is a cloud service provider where the infra is hosted
        checks/                        # -> This folder contains all checks under the provider.
          sub_folder_1/                # -> A sub-folder to define the hirerarchy. This can be nested.
            some_awesome_check_1.py    # -> A file that holds a class extending the Check class to be executed
            some_awesome_check_1.yaml  # -> Metadata associated to the check
            some_awesome_check_2.py    
            some_awesome_check_2.yaml
          sub_folder_2/                # -> A sub-folder to define the hirerarchy. This can be nested.
            some_awesome_check_1.py    # -> A file that holds a class extending the Check class to be executed
            some_awesome_check_1.yaml  # -> Metadata associated to the check
            some_awesome_check_2.py    
            some_awesome_check_2.yaml
          .
          .
          .
        frameworks/                    # -> A folder containing framework configurations
          framework_1.yaml             # -> A file containing the configuration for Sections and Checks to the framework
          war.yaml
          iso_27001.yaml
          pci_dss.yaml
          .
          .
          .
        profiles                       # -> A folder containing profiles that helps with inclusion and exclusion of checks
          profile_1.yaml               # -> A file that contains `include_checks` and `exclude_checks`
          startup.yaml
          bank.yaml
          corporate.yaml
          .
          .
          .
        utils                          # -> Utility functions for the checks can be added in this directory
        __init__.py
        provider.py
    scripts/                           # -> This folder contains one time scripts required for the project
    tests/                             # -> Project checks are written in this dir
    tevico/
      cli/
      engine/
        configs/
        core/
        entities/
          channel/
          check/
          framework/
          profile/
          provider/
          report/
      report/
      templates/
      __init__.py
    mkdocs.yml    # The configuration file.
