#!/bin/bash

# Configures remote syslog collection on CentOS, and configures event forwarding to Wazuh agent.
# Usage: ./syslog_setup.sh
# Author: Jeff Starke

# Configure rsyslog

read -p "Which syslog protocol would you like to be configured for? [udp/tcp]" proto

if [ $proto == udp ]; then
  sed -i '/imudp/s/^#//g' /etc/rsyslog.conf # Configure syslog for udp
  sed -i '/UDPServerRun/s/^#//g' /etc/rsyslog.conf # Configure syslog for udp
  firewall-cmd --permanent --add-port=514/udp
elif [ $proto == tcp ]; then
  sed -i '/imtcp/s/^#//g' /etc/rsyslog.conf # Configure syslog for tcp
  sed -i '/TCPServerRun/s/^#//g' /etc/rsyslog.conf # Configure syslog for tcp
   firewall-cmd --permanent --add-port=514/tcp
fi

# Add a template for all remote logs to be sent to /var/log/rsyslog

sed -i "21i if $fromhost-ip startswith 'xxx.xxx.xxx.' then /var/log/rsyslog" /etc/rsyslog.conf # Remote log template
sed -i "22i & ~" /etc/rsyslog.conf # Ends evaluation of logs after template match

# Add Wauh localfile monitoring for /var/log/rsyslog

sed -i '$s/^/  <localfile>\n/' /var/ossec/etc/ossec.conf
sed -i '$s/^/    <log_format>syslog<\/log_format>\n/' /var/ossec/etc/ossec.conf
sed -i '$s/^/    <location>\/var\/log\rsyslog<\/location>\n/' /var/ossec/etc/ossec.conf
sed -i '$s/^/  <\/localfile>\n/' /var/ossec/etc/ossec.conf
  
firewall-cmd --reload
systemctl restart rsyslog
systemctl restart wazuh-agent

cat << EOF

This device is now also configured to recieve syslog on port 514 (UDP by default), and forward it along to Wazuh.

EOF
