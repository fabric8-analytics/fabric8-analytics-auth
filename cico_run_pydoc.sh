#!/bin/bash

set -ex

prep() {
    yum -y –disableplugin=fastestmirror update
    yum -y install –disableplugin=fastestmirror epel-release
    yum -y install –disableplugin=fastestmirror python36 python36-virtualenv which
}

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

prep
check_python_version
./check-docstyle.sh
