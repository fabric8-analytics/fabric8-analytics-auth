#!/bin/bash -ex

prep() {
    # workaround for https://bugs.centos.org/view.php?id=16337 #
    echo -e "exclude=mirror.ci.centos.org" >> /etc/yum/pluginconf.d/fastestmirror.conf

    yum -y update
    yum -y install epel-release
    yum -y install gcc python36-pip python36-requests python36-devel docker git which python36-virtualenv make openssl-devel
    pip3 install pytest
    pip3 install docker-compose
    systemctl start docker
}

prep
