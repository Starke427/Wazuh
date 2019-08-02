#!/bin/bash

# Installs Suricata 4.1.4
# Usage: ./suricata_setup.sh [listening_interface: defaults to first interface]
# Author: Jeff Starke

### Suricata Installation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
interface=$(ifconfig | grep -m1 flag | cut -d":" -f1) # Grab server interface

# Install and test Suricata-4.1.4
yum install epel-release -y
yum install suricata-4.1.4 PyYAML -y
sudo suricata-update
sudo suricata-update update-sources
suricata -T

# Configure Suricata listener to restart on reboot with crontab and update at 0200 UTC on Tuesdays
crontab -l > mycron
echo "@reboot sudo suricata -c /etc/suricata/suricata.yaml -i ${1-$(ifconfig | grep -m1 flag | cut -d":" -f1)} -D" >> mycron
echo "* 2 * * * sudo suricata-update" >> mycron
crontab mycron
rm -f mycron

# Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i ${1-interface} -D

cat << EOF

Next step is to configure a SPAN/mirror port to forward to ${1-interface} so you can start picking up on lateral network traffic.

EOF
