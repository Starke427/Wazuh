# Wazuh

Wazuh is a free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.  

While the tools are publicly available, it is highly recommended that you have them professionally managed for you. A Managed Security Service is capable of managing the back-end maintenaince, troubleshooting, and tuning. They can also provide continuous monitoring, reporting, and investigation and escalation of security incidents. 

The scripts here-in will help you deploy a stand-alone server for proof-of-concepts, testing, and personal usage.

# wazuh_setup.sh

This script installs a stand-alone instance of Wazuh 3.9.2 on Elastic 7.1.1 and has been tested on CentOS 7.6.  
It is recommended you deploy this on a CentOS server with 4 vCPUs and at least 8GB RAM.  
The amount of storage provided is dependent on how long you hope to maintain immediately available logs.  

## Installation:

> git clone https://github.com/Starke427/Wazuh  
> cd Wazuh  
> chmod +x wazuh_setup.sh  
> ./wazuh_setup.sh



After installation completes, navigate to http://<Host_IP>:5601 to configure the Kibana app.  

When prompted for cluster information, the defaults are:  

Username: foo  
Password: bar  
Host URL: http://<Host_IP>  
Port: 55000  



After providing api credentials, navigate to Management > Kibana Index Patterns, select wazuh-alerts-3.x-* and click on the star in the top-right corner. From here, you can navigate to the Kibana app and start deploying agents. Agent installation scripts will have already been created for Linux, Windows, and MacOS in your /var/ossec/agent_scripts folder on the Manager.



## Notes:

It currently does not configure an nginx proxy for TLS  encyprtion.  

Once ran, it will use the first interface IP to configure everything, so it's recommended to run this on a fresh install.

This script will also create agent installation scripts under /var/ossec/agent_scripts.

By default, the manager can recieve syslog over UDP/514.

This Manager has been configured to use TCP/1514 for on-going communication with agents.

# suricata_setup.sh

This script automates the process of deploying suricata for network intrusion detection monitoring. It can be run on the Manager or an agent host. Ideally, this should be deployed on a host with a dedicated network interface for network monitoring. If an interface is not provided, the script will set up monitoring on the first interface it sees. It also sets cron tasks for daily rule updates.

# build_install_scripts.sh

This script automates the creation of installation scripts for the different operating systems. The wazuh_setup script already does this, but this is helpful for already deployed instances. The script will ask for your instance IP and authentication password and build installer scripts for CentOS/RedHat, Debian/Ubuntu, MacOS and Windows.

# rename_agents.sh

This script automates the process of renaming already deployed agents, and must be run on the Manager.
