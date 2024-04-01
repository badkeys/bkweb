#!/bin/bash
set -euo pipefail

# linters etc.
pycodestyle --max-line-length=88 --ignore=W503,E203,E501 wsgi/*.py
pyflakes wsgi/*.py
pyupgrade --py312-plus wsgi/*.py
black --check --diff wsgi/*.py

# security checks
flake8 --select=DUO wsgi/*.py
