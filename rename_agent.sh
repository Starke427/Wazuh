#!/bin/bash

# Useful for automating renaming agents. This must be run on the Wazuh Manager.

read -p "What is the agent's current name? " ori
read -p "What would you like to rename it to? " new

# Stop Wazuh.
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-api

# Perform agent renaming tasks.
mv /var/ossec/queue/agent-info/$ori-any /var/ossec/queue/agent-info/$new-any
mv /var/ossec/queue/rootcheck/\($ori\)\ any-\>rootcheck /var/ossec/queue/rootcheck/\($new\)\ any-\>rootcheck
sed -i "s/$ori/$new/g" /var/ossec/etc/client.keys

# Clean Wazuh databases.
rm -f /var/ossec/var/db/global.db* 
rm -f /var/ossec/var/db/.profile.db* 
rm -f /var/ossec/var/db/agents/*

# Restart Wazuh.
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-api
