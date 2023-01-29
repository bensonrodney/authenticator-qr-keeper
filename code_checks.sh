#!/bin/bash

set -euxo pipefail

_dirs="authentication_qr_keeper"

black --check ${_dirs}
isort --check ${_dirs}
flake8 ${_dirs}
pylint ${_dirs}

echo "Success!"
