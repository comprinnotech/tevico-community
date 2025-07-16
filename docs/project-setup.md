# Project Setup

If you are kneen on configuring the project and manually generating the report then you're at the right place.

Before you make any required changes to the project and follow along the CLI Params to execute it, you will first need to **set up the project** locally.

---

**TLDR;** You just want to copy paste and setup the project here's a snippet for you! Once you execute these commands, you can skip the **Project Setup** section.

```bash title="TLDR; Project Setup"
git clone https://github.com/comprinnotech/tevico-community.git
cd tevico-community

python3 -m venv .venv
source .venv/bin/activate

pip3 install poetry
poetry install
```

---

## Project Setup

Setting up the project involves a few simple steps. Follow the instructions below to get your environment ready.

**Step 1**: Clone the repository to your local machine. This will download all the necessary files for the project.

```bash title="Clone repo"
git clone https://github.com/comprinnotech/tevico-community.git

cd tevico-community
```

**Step 2**: Create a Python virtual environment and activate it. This ensures that all dependencies are installed in an isolated environment, preventing conflicts with other projects.

```bash title="Initialise Virtual Environment"
python3 -m venv .venv

source .venv/bin/activate
```

**Step 3**: Install Poetry, a dependency management tool for Python. Poetry will help you manage the project's dependencies and virtual environments more efficiently.

```bash title="Setup Poetry"
pip3 install poetry
```

**Step 4**: Use Poetry to install all the project dependencies. This will download and install all the required packages specified in the `pyproject.toml` file.

```bash title="Install Dependencies"
poetry install
```

The project setup is now complete! For information on how to run the project using various command-line parameters, please refer to the [CLI Parameters](cli-params.md) page.