#!/bin/bash

set -ex

prep() {
    # workaround for https://bugs.centos.org/view.php?id=16337 #
    echo -e "exclude=mirror.ci.centos.org" >> /etc/yum/pluginconf.d/fastestmirror.conf

    yum -y update
    yum -y install epel-release
    yum -y install python36 python36-virtualenv which
}

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

# this script is copied by CI, we don't need it
rm -f env-toolkit

prep
check_python_version
./qa/detect-common-errors.sh
./qa/detect-dead-code.sh
./qa/measure-cyclomatic-complexity.sh --fail-on-error
./qa/measure-maintainability-index.sh --fail-on-error
./qa/run-linter.sh
