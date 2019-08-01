#!/bin/bash

# Wazuh agent installation script generator.
# Author: Jeff Starke
# Tested on MacOS Mohave 10.14
#
# Usage; ./build_wazuh_agents.sh

echo ""
read -p "What is the Wazuh instance FQDN or IP? " local_ip
echo ""
read -p "What is the agent registration password? " auth_pass
echo ""

# Create agent installation scripts.
dir=$(pwd)
sudo mkdir $dir/agent_scripts

#CentOS 7 (wazuh_install_rpm.sh)
echo "rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum
protect=1
EOF
WAZUH_MANAGER_IP=\"$local_ip\" WAZUH_PROTOCOL=\"tcp\" WAZUH_PASSWORD=\"$auth_pass\" WAZUH_GROUP=\"linux\" yum install wazuh-agent -y
sed -i \"s/^enabled=1/enabled=0/\" /etc/yum.repos.d/wazuh.repo # Disable Wazuh repo
" | sudo tee $dir/agent_scripts/wazuh_install_rpm.sh

#Debian/Ubuntu (wazuh_install_deb.sh)
echo "apt-get install curl apt-transport-https lsb-release gnupg2
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER_IP=\"$local_ip\" WAZUH_PROTOCOL=\"tcp\" WAZUH_PASSWORD=\"$auth_pass\" WAZUH_GROUP=\"linux\" apt-get install wazuh-agent -y
sed -i \"s/^deb/#deb/\" /etc/apt/sources.list.d/wazuh.list
apt-get update
" | sudo tee $dir/agent_scripts/wazuh_install_deb.sh


#Windows, Must be run from Admin Powershell (wazuh_install.ps1), 2003/XP can be manually installed.
echo "Invoke-WebRequest https://packages.wazuh.com/3.x/windows/wazuh-agent-3.9.2-1.msi -OutFile C:\wazuh-agent-3.9.2-1.msi
Start-Process C:\wazuh-agent-3.9.2-1.msi -ArgumentList '/q ADDRESS=\"$local_ip\" AUTHD_SERVER=\"$local_ip\" PROTOCOL=\"TCP\" PASSWORD=\"$auth_pass\" GROUP=\"windows\"' -Wait
" | sudo tee $dir/agent_scripts/wazuh_install.ps1


#MacOS
echo "curl -O https://packages.wazuh.com/3.x/osx/wazuh-agent-3.9.2-1.pkg
launchctl setenv WAZUH_MANAGER_IP \"$local_ip\" WAZUH_PROTOCOL \"TCP\" WAZUH_PASSWORD \"$auth_pass\" WAZUH_GROUP \"macos\" && installer -pkg wazuh-agent-3.9.2-1.pkg -target /
" | sudo tee $dir/agent_scripts/wazuh_install_macos.sh


cat << EOF # Finish agent scripts

Agent installation scripts have been pre-configured based on the instance IP and authd password.
CentOS/RHEL  |  Debian/Ubuntu  |  Amazon Linux  |  Windows  |  MacOS

Installation scripts can be found in $dir/agent_scripts
EOF
