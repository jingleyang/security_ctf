#!/bin/bash

APT_GET="sudo apt-get -y install"

$APT_GET python python-sqlalchemy

$APT_GET python-dpkt python-jinja2 python-magic python-pymongo python-libvirt python-bottle python-pefile ssdeep

sudo pip -q install pydeep

$APT_GET build-essential git libpcre3 libpcre3-dev libpcre++-dev automake yara 

#tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump

# Linux kernel
$APT_GET linux-headers-`uname -r`

$APT_GET libsdl1.2debian

curl -o virtualbox.dev -L "http://download.virtualbox.org/virtualbox/5.1.2/virtualbox-5.1_5.1.2-108956i~Ubuntu~trusty_amd64.deb"
sudo dpkg -i ./virtualbox.deb	

# cuckoo
git clone https://github.com/cuckoosandbox/cuckoo 

sudo  /etc/init.d/vboxdrv setup

sudo adduser cuckoo
sudo usermod -G vboxusers cuckoo
sudo usermod -G libvirtd cuckoo

