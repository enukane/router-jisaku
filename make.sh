#!/bin/sh
if [ -d ~/vagrant ]; then
    rm -rf ~/vagrant
fi
cp -r /vagrant ~/vagrant
cd ~/vagrant

cd ~/vagrant/chap2-ltest
make