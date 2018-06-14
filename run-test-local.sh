#! /bin/bash

PYTHONPATH=$(pwd)/f8a_auth/
export PYTHONPATH

function prepare_venv() {
    virtualenv -p python3 venv && source venv/bin/activate && python3 "$(which pip3)" install -r requirements.txt && python3 "$(which pip3)" install -r test_requirements.txt
}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

cd tests || exit
PYTHONDONTWRITEBYTECODE=1 python3 "$(which pytest)" --cov=../f8a_auth/ --cov-report term-missing -vv -s .
