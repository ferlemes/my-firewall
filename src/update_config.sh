#!/bin/bash

python3 main.py || exit 1

cp netplan.yaml /etc/netplan/50-cloud-init.yaml
netplan apply || exit 1

cp dhcpd.conf /etc/dhcp/dhcpd.conf
cp dhcpd6.conf /etc/dhcp/dhcpd6.conf
dhcpd -t -cf /etc/dhcp/dhcpd.conf || exit 1
dhcpd -t -cf /etc/dhcp/dhcpd6.conf || exit 1
systemctl restart isc-dhcp-server
systemctl status isc-dhcp-server
