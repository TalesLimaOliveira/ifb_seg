.PHONY: virtualenv install ipython fmt test clean

virtualenv:
	@python -m venv .venv

install:
	@echo "Installing requirements"
	@.venv/bin/python -m pip install -r requirements.txt

ipython:
	@.venv/bin/ipython

fmt:
	@.venv/bin/isort cryp tests
	@.venv/bin/black cryp tests

test:
	@.venv/bin/pytest -s -vv

clean:
	@find ./ -name '*.pyc' -exec rm -f {} \;
	@find ./ -name '__pycache__' -exec rm -f {} \;
	@find ./ -name 'Thumbs.db' -exec rm -f {} \;
	@find ./ -name '*~' -exec rm -f {} \;
	@rm -rf .cache
	@rm -rf .pytest_cache
	@rm -rf .mypy_cache
	@rm -rf build
	@rm -rf dist
	@rm -rf *.egg-info
	@rm -rf htmlcov
	@rm -rf .tox/
	@rm -rf docs/_build
