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

### Wazuh agent configuration

# Configure rsyslog
sed -i '/imudp/s/^#//g' /etc/rsyslog.conf # Configure syslog for udp
sed -i '/UDPServerRun/s/^#//g' /etc/rsyslog.conf # Configure syslog for udp
firewall-cmd --permanent --add-port=514/udp
# sed -i '/imtcp/s/^#//g' /etc/rsyslog.conf # Configure syslog for tcp
# sed -i '/TCPServerRun/s/^#//g' /etc/rsyslog.conf # Configure syslog for tcp
#firewall-cmd --permanent --add-port=514/tcp

# All messages go to /var/log/messages by default, this can create suricata.log

# sed -i '21i $template RemoteLogs,"/var/log/suricata.log"' /etc/rsyslog.conf # Remote log template, push to suricata.log
# sed -i '22i *.* ?RemoteLogs' /etc/rsyslog.conf # Remote log template, matches everything
# sed -i '23i & stop' /etc/rsyslog.conf # Ends evaluation of logs after template match

systemctl restart rsyslog
firewall-cmd --reload

# Create localfile configuration in /var/ossec/etc/ossec.conf
# All messages go to /var/log/messages by default, this can create suricata.log monitoring

# sed '$i ' /var/ossec/etc/ossec.conf
# sed '$i  <localfile>' /var/ossec/etc/ossec.conf
# sed '$i    <log_format>syslog</log_format>' /var/ossec/etc/ossec.conf
# sed '$i    <location>/var/log/suricata.log</location>' /var/ossec/etc/ossec.conf # Designate the file path here
# sed '$i ' /var/ossec/etc/ossec.conf

cat << EOF

Next step is to configure a SPAN/mirror port to forward to ${1-interface} so you can start picking up on lateral network traffic.

EOF
