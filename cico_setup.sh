#!/bin/bash -ex

prep() {
    yum -y update
    yum -y install epel-release
    yum -y install gcc python36-pip python36-requests python36-devel docker git which python36-virtualenv
    pip3 install pytest
    pip3 install docker-compose
    systemctl start docker
}

prep
