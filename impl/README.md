## Creating a Development Environment
To create a development environment, you can use the following command:

```bash
make virtualenv # python -m venv .venv
```

## Activating the Virtual Environment
To activate the virtual environment, run the following command (or use Git Bash on Windows):

```bash
source .venv/bin/activate
```

## Installing Dependencies
After activating the virtual environment, you can install dependencies without affecting the system's Python environment:

```bash
pip install --upgrade pip # Not required, but a good practice to update pip
make install # pip install -r requirements.txt
```

## Running Tests
If everything is set up correctly, you can run tests to validate the environment:

```bash
make test # pytest -s -vv
```

## Observation
If you don't have make installed, you can execute the commands individually found in the Makefile:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pytest -s -vv tests/
```
