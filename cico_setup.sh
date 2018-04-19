#!/bin/bash -ex

prep() {
    yum -y update
    yum -y install epel-release
    yum -y install gcc python34-pip python34-requests python34-devel docker git which python34-virtualenv
    pip3 install pytest
    pip3 install docker-compose
    systemctl start docker
}

prep
