# Wazuh

Wazuh is a free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.  

While the tools are publicly available, it is highly recommended that you have them professionally managed for you. A Managed Security Service is capable of managing the back-end maintenaince, troubleshooting, and tuning. They can also provide on-going tuning, reporting, and, most importantly, investigation and alerting on security incidents.  

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

# rename_agents.sh

This script automates the process of renaming already deployed agents, and must be run on the Manager.
